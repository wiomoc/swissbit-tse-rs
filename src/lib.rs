extern crate byteorder;
#[cfg(windows)]
extern crate windows;

#[cfg(linux)]
extern crate libc;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum TseError {
    IO(std::io::Error),
    Win(windows::core::Error),
    Timeout,
    CmdError(u16, Vec<u8>),
}

impl From<std::io::Error> for TseError {
    fn from(value: std::io::Error) -> Self {
        TseError::IO(value)
    }
}

pub type Result<T> = std::result::Result<T, TseError>;

const BLOCK_SIZE: usize = 512;

#[cfg(windows)]
fn open_file_direct(filename: OsString) -> Result<File> {
    use windows::core::PCSTR;
    use windows::Win32::Storage::FileSystem;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, FILE_READ_DATA, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING,
    };

    let filename = CString::new(filename.to_str().unwrap()).unwrap();
    unsafe {
        let handle = FileSystem::CreateFileA(
            PCSTR(filename.as_ptr() as *const u8),
            FILE_READ_DATA | FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
            None,
        )
        .map_err(TseError::Win)?;
        Ok(File::from_raw_handle(handle.0 as RawHandle))
    }
}

#[cfg(linux)]
fn open_file_direct(filename: OsString) -> Result<File> {
    let filename = CString::new(filename.to_str().unwrap()).unwrap();
    unsafe {
        let fd = libc::open(
            filename.as_ptr(),
            libc::O_DIRECT | libc::O_SYNC | libc::O_RDWR,
        );

        if fd == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(File::from_raw_fd(fd))
    }
}

#[derive(Debug)]
pub enum InitializationState {
    Uninitialized = 0,
    Initialized = 1,
    Decommissioned = 2,
}

pub enum UserId {
    Unauthenticated = 0,
    Admin = 1,
    TimeAdmin = 2,
}

impl InitializationState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Uninitialized,
            1 => Self::Initialized,
            2 => Self::Decommissioned,
            _ => panic!("invalid enum value"),
        }
    }
}

#[derive(Debug)]
pub struct SignedTransaction {
    transaction_id: u64,
    serial: Vec<u8>,
    log_time: u64,
    signature_counter: u64,
    signature: Vec<u8>,
}

#[derive(Debug)]
pub struct TseInfo {
    description: String,
    public_key: Vec<u8>,
    serial_number: Vec<u8>,
    size: u32,
    certificate_expiration_date: u32,
    software_version: u32,
    created_signatures: u32,
    max_signatures: u32,
    registered_clients: u32,
    max_registered_client: u32,
    time_until_next_self_test: u32,
    time_until_next_time_synchronization: u32,
    tar_export_size: u64,
    has_passed_self_test: bool,
    has_valid_time: bool,
    has_changed_puk: bool,
    has_changed_admin_pin: bool,
    has_changed_time_admin_pin: bool,

    initialization_state: InitializationState,
    is_transaction_in_progress: bool,
}

impl TseInfo {
    pub fn read<P: AsRef<Path>>(path: P) -> Result<TseInfo> {
        let filename = path
            .as_ref()
            .with_file_name("TSE_INFO.DAT")
            .into_os_string();
        let mut info_file_contents = vec![0u8; BLOCK_SIZE];
        open_file_direct(filename)?.read_exact(&mut info_file_contents)?;

        let read_int = |pos: usize| BigEndian::read_u32(&info_file_contents[pos..pos + 4]);
        Ok(TseInfo {
            description: String::from_utf8_lossy(
                &info_file_contents[0x120
                    ..0x120
                        + (&info_file_contents[0x120..])
                            .iter()
                            .position(|b| *b == b'\0')
                            .unwrap()],
            )
            .to_string(),
            public_key: info_file_contents[0x6b..0x6b + info_file_contents[0x6a] as usize].to_vec(),
            serial_number: info_file_contents[0x100..0x120].to_vec(),
            size: read_int(0x18),
            software_version: read_int(0x54),
            created_signatures: read_int(0x30),
            max_signatures: read_int(0x34),
            registered_clients: read_int(0x38),
            max_registered_client: read_int(0x3c),
            certificate_expiration_date: read_int(0x40),
            has_valid_time: (info_file_contents[0x1c] & 1) == 1,
            has_passed_self_test: (info_file_contents[0x1c] & 2) == 2,
            initialization_state: InitializationState::from_u8(info_file_contents[0x1d]),
            time_until_next_self_test: read_int(0x24),
            time_until_next_time_synchronization: read_int(0xd0),
            tar_export_size: BigEndian::read_u64(&info_file_contents[0x48..(0x48 + 9)]),
            is_transaction_in_progress: info_file_contents[0x1e] != 0,
            has_changed_puk: (info_file_contents[0x20] & 1) == 1,
            has_changed_admin_pin: (info_file_contents[0x20] & 2) == 2,
            has_changed_time_admin_pin: (info_file_contents[0x20] & 4) == 4,
        })
    }
}

struct TseCommunication {
    file: File,
}

impl TseCommunication {
    fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let filename = path
            .as_ref()
            .with_file_name("TSE_COMM.DAT")
            .into_os_string();
        let file = open_file_direct(filename)?;
        Ok(TseCommunication { file })
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(buffer)?;
        Ok(())
    }

    fn write(&mut self, buffer: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(buffer)?;
        Ok(())
    }

    fn write_command(&mut self, cmd: &[u8]) -> Result<()> {
        let mut buf = Cursor::new(vec![0u8; BLOCK_SIZE]);
        buf.write_u16::<BigEndian>(cmd.len() as u16).unwrap();
        buf.write(cmd).unwrap();
        self.write(buf.get_ref())
    }

    pub(crate) fn send_command(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        let mut read_buf = [0u8; BLOCK_SIZE];
        self.read(&mut read_buf)?;
        let before_counter = BigEndian::read_u32(&read_buf[0..4]);
        self.write_command(cmd)?;

        let max_trys = 3000;
        for _ in 0..max_trys {
            self.read(&mut read_buf)?;
            let response_counter = BigEndian::read_u32(&read_buf[0..4]);
            let response_status = read_buf[4];
            if response_status == 0xf3
            /*|| response_counter == before_counter*/
            {
                thread::sleep(Duration::from_millis(150));
            } else if response_status == 0xfd {
                self.write_command(&[0x83, 0])?;
            } else if response_status == 0xff {
                let response_len = BigEndian::read_u16(&read_buf[5..7]);
                let cmd_status = BigEndian::read_u16(
                    &read_buf[(response_len as usize + 5)..(response_len as usize + 7)],
                );
                let response_data = read_buf[7..response_len as usize + 5].to_vec();
                return if cmd_status != 0 {
                    Err(TseError::CmdError(cmd_status, response_data))
                } else {
                    Ok(response_data)
                };
            }
        }
        return Err(TseError::Timeout);
    }
}

struct TseTarFiles {
    files: Vec<File>,
}

impl TseTarFiles {
    fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut files = Vec::new();
        for file_num in 1..100 {
            let filename = path
                .as_ref()
                .with_file_name(format!("TSE_TAR.{number:0>3}", number = file_num))
                .into_os_string();
            if let Ok(file) = open_file_direct(filename) {
                files.push(file);
            } else {
                break;
            }
        }
        return Ok(Self { files });
    }

    fn write(&mut self, block_offset: usize, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut data = &data[..];
        let mut block_offset = block_offset;
        while data.len() > 0 {
            let file_total_blocks = 2097152;
            let file_index = block_offset / file_total_blocks;
            if file_index > self.files.len() {
                panic!("invalid param")
            }
            let file = &mut self.files[file_index];
            file.seek(SeekFrom::Start(
                ((block_offset % file_total_blocks) * BLOCK_SIZE) as u64,
            ))?;
            if data.len() >= BLOCK_SIZE {
                file.write_all(&data[..BLOCK_SIZE])?;
                data = &data[BLOCK_SIZE..];
                block_offset += BLOCK_SIZE
            } else {
                let mut buf = vec![0u8; BLOCK_SIZE];
                buf[..data.len()].copy_from_slice(data);
                file.write_all(&buf)?;
                break;
            }
        }

        Ok(())
    }
}

pub struct Tse {
    conn: TseCommunication,
    store: TseTarFiles,
}

impl Tse {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Tse {
            conn: TseCommunication::open(path.as_ref())?,
            store: TseTarFiles::open(path)?,
        })
    }

    pub fn run_selftest(&mut self, client_id: &str) -> Result<()> {
        let mut cmd = vec![0x40, 0, client_id.len() as u8];
        cmd.extend_from_slice(client_id.as_bytes());
        self.conn.send_command(&cmd)?;
        Ok(())
    }

    pub fn login(&mut self, user_id: UserId, pin: &str) -> Result<()> {
        let mut cmd = vec![0x20, 0, user_id as u8, pin.len() as u8];
        cmd.extend_from_slice(pin.as_bytes());
        self.conn.send_command(&cmd)?;
        Ok(())
    }

    pub fn update_time(&mut self, timestamp: u64) -> Result<()> {
        let mut cmd = Cursor::new(Vec::with_capacity(10));
        cmd.write_all(&[0x80, 0]).unwrap();
        cmd.write_u64::<BigEndian>(timestamp).unwrap();
        self.conn.send_command(cmd.get_ref())?;
        Ok(())
    }

    pub fn read_certificate(&mut self) -> Result<Vec<u8>> {
        let mut cert = Vec::new();
        loop {
            let mut cmd = vec![0x86, 0, 0, 0, 0, 0];
            BigEndian::write_u32(&mut cmd[2..], cert.len() as u32);
            match self.conn.send_command(&cmd) {
                Ok(response) => {
                    let response_len = BigEndian::read_u16(&response[..2]);
                    if response_len == 0 {
                        return Ok(cert);
                    }
                    cert.extend_from_slice(&response[2..])
                }
                Err(TseError::CmdError(1, _)) => return Ok(cert),
                Err(e) => return Err(e),
            }
        }
    }

    pub fn list_started_transactions(&mut self, client_id: &str) -> Result<Vec<u64>> {
        let mut transaction_ids = Vec::new();
        loop {
            let mut cmd = vec![0x85, 0, 0, 0, 0, 0, client_id.len() as u8];
            BigEndian::write_u32(&mut cmd[2..], transaction_ids.len() as u32);
            cmd.extend_from_slice(client_id.as_bytes());
            match self.conn.send_command(&cmd) {
                Ok(response) => {
                    let amount = response[0];
                    transaction_ids.extend(
                        response[1..]
                            .chunks(8)
                            .take(amount as usize)
                            .map(BigEndian::read_u64),
                    );
                    if amount < 62 {
                        return Ok(transaction_ids);
                    }
                }
                Err(TseError::CmdError(1, _)) => return Ok(transaction_ids),
                Err(e) => return Err(e),
            }
        }
    }

    pub fn register_client(&mut self, client_id: &str) -> Result<()> {
        let mut cmd = vec![0x41, 0, client_id.len() as u8];
        cmd.extend_from_slice(client_id.as_bytes());
        self.conn.send_command(&cmd)?;
        Ok(())
    }

    pub fn deregister_client(&mut self, client_id: &str) -> Result<()> {
        let mut cmd = vec![0x42, 0, client_id.len() as u8];
        cmd.extend_from_slice(client_id.as_bytes());
        self.conn.send_command(&cmd)?;
        Ok(())
    }

    pub fn enable_ctss_interface(&mut self) -> Result<()> {
        self.conn.send_command(&[0x60, 0])?;
        Ok(())
    }

    pub fn disable_ctss_interface(&mut self) -> Result<()> {
        self.conn.send_command(&[0x61, 0])?;
        Ok(())
    }

    pub fn initialize(&mut self) -> Result<()> {
        self.conn.send_command(&[0x70, 0])?;
        Ok(())
    }

    pub fn list_clients(&mut self) -> Result<Vec<String>> {
        let mut clients = vec![];
        loop {
            let mut cmd = vec![0x43, 0, 0, 0, 0, 0];
            BigEndian::write_u32(&mut cmd[2..], clients.len() as u32);
            match self.conn.send_command(&cmd) {
                Ok(response) => {
                    let amount_clients = response[0];
                    clients.extend(response[1..].chunks(32).take(amount_clients as usize).map(
                        |chunk| {
                            String::from_utf8_lossy(
                                &chunk[..chunk.iter().position(|b| *b == b'\0').unwrap()],
                            )
                            .to_string()
                        },
                    ));

                    if amount_clients < 16 {
                        return Ok(clients);
                    }
                }
                Err(TseError::CmdError(1, _)) => return Ok(clients),
                Err(e) => return Err(e),
            }
        }
    }

    fn open_transaction(
        &mut self,
        client_id: &str,
        transaction_event: u8,
        transaction_id: u64,
        process_data_length: u64,
        process_type: &str,
    ) -> Result<usize> {
        let mut cmd = Cursor::new(Vec::new());
        cmd.write_all(&[0x90, 0, transaction_event, client_id.len() as u8])
            .unwrap();
        cmd.write_all(client_id.as_bytes()).unwrap();
        cmd.write_u64::<BigEndian>(transaction_id).unwrap();
        cmd.write_u64::<BigEndian>(process_data_length).unwrap();
        cmd.write_u64::<BigEndian>(process_type.len() as u64)
            .unwrap();
        cmd.write_all(process_type.as_bytes()).unwrap();
        cmd.write_u64::<BigEndian>(0).unwrap();
        let block_offset_response = self.conn.send_command(cmd.get_ref())?;
        Ok(BigEndian::read_u64(&block_offset_response) as usize)
    }

    fn close_transaction(&mut self) -> Result<SignedTransaction> {
        let mut response = Cursor::new(self.conn.send_command(&[0x95, 0])?);
        let transaction_id = response.read_u64::<BigEndian>().unwrap();
        let mut serial = vec![0u8; 32];
        response.read_exact(&mut serial).unwrap();
        let log_time = response.read_u64::<BigEndian>().unwrap();
        let signature_counter = response.read_u64::<BigEndian>().unwrap();
        let signature_len = response.read_u64::<BigEndian>().unwrap();
        let mut signature = vec![0u8; signature_len as usize];
        response.read_exact(&mut signature).unwrap();
        Ok(SignedTransaction {
            transaction_id,
            serial,
            log_time,
            signature_counter,
            signature,
        })
    }

    pub fn persist_transaction(
        &mut self,
        client_id: &str,
        transaction_event: u8,
        transaction_id: u64,
        process_type: &str,
        process_data: &[u8],
    ) -> Result<SignedTransaction> {
        let block_offset = self.open_transaction(
            client_id,
            transaction_event,
            transaction_id,
            process_data.len() as u64,
            process_type,
        )?;
        self.store.write(block_offset, process_data)?;
        self.close_transaction()
    }
}
