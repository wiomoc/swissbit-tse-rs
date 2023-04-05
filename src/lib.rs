extern crate byteorder;
#[cfg(target_os = "windows")]
extern crate windows;

#[cfg(target_os = "linux")]
extern crate libc;

extern crate maligned;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

#[cfg(target_os = "windows")]
use std::os::windows::io::{FromRawHandle, RawHandle};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use maligned::{A512, align_first_boxed_cloned};

#[derive(Debug)]
pub enum TseError {
    IO(std::io::Error),
    #[cfg(target_os = "windows")]
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

pub const ERROR_INVALID_PARAMETER: u16 = 4103;
pub const ERROR_NO_TIME_SET: u16 = 4098;
pub const ERROR_NOT_AUTHORIZED: u16 = 4111;
pub const ERROR_CLIENT_NOT_REGISTERED: u16 = 4113;
pub const ERROR_NEEDS_ACTIVE_CTSS: u16 = 4179;
pub const ERROR_NEEDS_SELF_TEST: u16 = 4180;
pub const ERROR_NEEDS_SELF_TEST_PASSED: u16 = 4181;
pub const ERROR_NOT_INITIALIZED: u16 = 4351;

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "linux")]
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

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TransactionEvent {
    Start = 0,
    Update = 1,
    Finish = 2,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum InitializationState {
    Uninitialized = 0,
    Initialized = 1,
    Decommissioned = 2,
}

#[derive(Debug, PartialEq, Copy, Clone)]
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
    pub transaction_id: u64,
    pub serial: Vec<u8>,
    pub log_time: u64,
    pub signature_counter: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct TseInfo {
    pub description: String,
    pub public_key: Vec<u8>,
    pub serial_number: Vec<u8>,
    pub size: u32,
    pub certificate_expiration_date: u32,
    pub software_version: u32,
    pub created_signatures: u32,
    pub max_signatures: u32,
    pub registered_clients: u32,
    pub max_registered_client: u32,
    pub time_until_next_self_test: u32,
    pub time_until_next_time_synchronization: u32,
    pub tar_export_size: u64,
    pub has_passed_self_test: bool,
    pub has_valid_time: bool,
    pub has_changed_puk: bool,
    pub has_changed_admin_pin: bool,
    pub has_changed_time_admin_pin: bool,
    pub initialization_state: InitializationState,
    pub is_transaction_in_progress: bool,
}

impl TseInfo {
    pub fn read<P: AsRef<Path>>(path: P) -> Result<TseInfo> {
        let filename = path
            .as_ref()
            .join("TSE_INFO.DAT")
            .into_os_string();
        let mut info_file_contents = align_first_boxed_cloned::<u8, A512>(BLOCK_SIZE, 0u8);
        open_file_direct(filename)?.read_exact(&mut info_file_contents)?;

        let read_int = |pos: usize| BigEndian::read_u32(&info_file_contents[pos..pos + 4]);
        Ok(TseInfo {
            description: String::from_utf8_lossy(
                &info_file_contents[0x120
                    ..0x120
                        + info_file_contents[0x120..]
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

pub struct TseCommunication {
    file: File,
}

impl TseCommunication {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let filename = path
            .as_ref()
            .join("TSE_COMM.DAT")
            .into_os_string();
        let file = open_file_direct(filename)?;
        Ok(TseCommunication { file })
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<()> {
        assert_eq!(buffer.len(), BLOCK_SIZE);
        self.file.seek(SeekFrom::Start(0))?;
        let bytes_read = self.file.read(buffer)?;
        assert_eq!(bytes_read, BLOCK_SIZE);
        Ok(())
    }

    fn write(&mut self, buffer: &[u8]) -> Result<()> {
        assert_eq!(buffer.len(), BLOCK_SIZE);
        self.file.seek(SeekFrom::Start(0))?;
        let bytes_written = self.file.write(buffer)?;
        assert_eq!(bytes_written, BLOCK_SIZE);
        Ok(())
    }

    fn write_command(&mut self, cmd: &[u8]) -> Result<()> {
        let mut buf = align_first_boxed_cloned::<u8, A512>(BLOCK_SIZE, 0);
        BigEndian::write_u16(&mut buf[..2], cmd.len() as u16);
        buf[2..(2 + cmd.len())].copy_from_slice(cmd);
        self.write(&buf)
    }

    fn send_command(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        let mut read_buf = align_first_boxed_cloned::<u8, A512>(BLOCK_SIZE, 0);
        self.read(&mut read_buf)?;
        let _before_counter = BigEndian::read_u32(&read_buf[0..4]);
        self.write_command(cmd)?;

        let max_trys = 3000;
        for _ in 0..max_trys {
            self.read(&mut read_buf)?;
            let _response_counter = BigEndian::read_u32(&read_buf[0..4]);
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
        Err(TseError::Timeout)
    }

    pub fn run_selftest(&mut self, client_id: &str) -> Result<()> {
        let mut cmd = vec![0x40, 0, client_id.len() as u8];
        cmd.extend_from_slice(client_id.as_bytes());
        self.send_command(&cmd)?;
        Ok(())
    }

    pub fn login(&mut self, user_id: UserId, pin: &str) -> Result<()> {
        let mut cmd = vec![0x20, 0, user_id as u8, pin.len() as u8];
        cmd.extend_from_slice(pin.as_bytes());
        self.send_command(&cmd)?;
        Ok(())
    }

    pub fn update_time(&mut self, timestamp: u64) -> Result<()> {
        let mut cmd = Cursor::new(Vec::with_capacity(10));
        cmd.write_all(&[0x80, 0]).unwrap();
        cmd.write_u64::<BigEndian>(timestamp).unwrap();
        self.send_command(cmd.get_ref())?;
        Ok(())
    }

    pub fn read_certificate(&mut self) -> Result<Vec<u8>> {
        let mut cert = Vec::new();
        loop {
            let mut cmd = vec![0x86, 0, 0, 0, 0, 0];
            BigEndian::write_u32(&mut cmd[2..], cert.len() as u32);
            match self.send_command(&cmd) {
                Ok(response) => {
                    let response_len = BigEndian::read_u16(&response[..2]);
                    if response_len == 0 {
                        return Ok(cert);
                    }
                    cert.extend_from_slice(&response[2..])
                }
                Err(TseError::CmdError(ERROR_INVALID_PARAMETER, _)) => return Ok(cert),
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
            match self.send_command(&cmd) {
                Ok(response) => {
                    if response.is_empty() {
                        return Ok(transaction_ids)
                    }
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
                Err(TseError::CmdError(ERROR_INVALID_PARAMETER, _)) => return Ok(transaction_ids),
                Err(e) => return Err(e),
            }
        }
    }

    pub fn register_client(&mut self, client_id: &str) -> Result<()> {
        let mut cmd = vec![0x41, 0, client_id.len() as u8];
        cmd.extend_from_slice(client_id.as_bytes());
        self.send_command(&cmd)?;
        Ok(())
    }

    pub fn deregister_client(&mut self, client_id: &str) -> Result<()> {
        let mut cmd = vec![0x42, 0, client_id.len() as u8];
        cmd.extend_from_slice(client_id.as_bytes());
        self.send_command(&cmd)?;
        Ok(())
    }

    pub fn enable_ctss_interface(&mut self) -> Result<()> {
        self.send_command(&[0x60, 0])?;
        Ok(())
    }

    pub fn disable_ctss_interface(&mut self) -> Result<()> {
        self.send_command(&[0x61, 0])?;
        Ok(())
    }

    pub fn initialize(&mut self) -> Result<()> {
        self.send_command(&[0x70, 0])?;
        Ok(())
    }

    pub fn list_clients(&mut self) -> Result<Vec<String>> {
        let mut clients = vec![];
        loop {
            let mut cmd = vec![0x43, 0, 0, 0, 0, 0];
            BigEndian::write_u32(&mut cmd[2..], clients.len() as u32);
            match self.send_command(&cmd) {
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
                Err(TseError::CmdError(ERROR_INVALID_PARAMETER, _)) => return Ok(clients),
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
        let block_offset_response = self.send_command(cmd.get_ref())?;
        Ok(BigEndian::read_u64(&block_offset_response) as usize)
    }

    fn close_transaction(&mut self) -> Result<SignedTransaction> {
        let mut response = Cursor::new(self.send_command(&[0x95, 0])?);
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
                .join(format!("TSE_TAR.{number:0>3}", number = file_num))
                .into_os_string();
            if let Ok(file) = open_file_direct(filename) {
                files.push(file);
            } else {
                break;
            }
        }
        Ok(Self { files })
    }

    fn write(&mut self, block_offset: usize, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut data = data;
        let mut block_offset = block_offset;
        while !data.is_empty() {
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
                let mut buf =align_first_boxed_cloned::<u8, A512>(BLOCK_SIZE, 0u8);
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
    time_admin_pin: String,
}

impl Tse {
    pub fn open<P: AsRef<Path>>(path: P, time_admin_pin: String) -> Result<Self> {
        Ok(Tse {
            conn: TseCommunication::open(path.as_ref())?,
            store: TseTarFiles::open(path)?,
            time_admin_pin,
        })
    }

    pub fn register_client(&mut self, client_id: &str, admin_pin: Option<&str>) -> Result<()> {
        self.retry_command(
            None,
            |tse| match tse.conn.register_client(client_id) {
                Err(TseError::CmdError(ERROR_NOT_AUTHORIZED, ..)) if admin_pin.is_some() => {
                    tse.conn.login(UserId::Admin, admin_pin.unwrap())?;
                    tse.conn.register_client(client_id)
                }
                e => e,
            },
            3,
        )
    }

    pub fn list_started_transactions(&mut self, client_id: &str) -> Result<Vec<u64>> {
        self.retry_command(
            Some(client_id),
            |tse| tse.conn.list_started_transactions(client_id),
            3,
        )
    }

    pub fn list_clients(&mut self) -> Result<Vec<String>> {
        self.retry_command(None, |tse| tse.conn.list_clients(), 3)
    }

    pub fn read_certificate(&mut self) -> Result<Vec<u8>> {
        self.retry_command(None, |tse| tse.conn.read_certificate(), 3)
    }

    pub fn persist_transaction(
        &mut self,
        client_id: &str,
        transaction_event: TransactionEvent,
        transaction_id: u64,
        process_type: &str,
        process_data: &[u8],
    ) -> Result<SignedTransaction> {
        let block_offset = self.retry_command(
            Some(client_id),
            move |tse| {
                tse.conn.open_transaction(
                    client_id,
                    transaction_event as u8,
                    transaction_id,
                    process_data.len() as u64,
                    process_type,
                )
            },
            4,
        )?;
        self.store.write(block_offset, process_data)?;
        self.retry_command(Some(client_id), |tse| tse.conn.close_transaction(), 2)
    }

    fn retry_command<T, F: Fn(&mut Tse) -> Result<T>>(
        &mut self,
        client_id: Option<&str>,
        fun: F,
        max_trys: u8,
    ) -> Result<T> {
        if max_trys == 0 {
            return Err(TseError::Timeout);
        }
        match fun(self) {
            Err(TseError::CmdError(ERROR_NO_TIME_SET, ..)) => {
                self.conn.update_time(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                )?;
                self.retry_command(client_id, fun, max_trys - 1)
            }
            Err(TseError::CmdError(ERROR_NEEDS_SELF_TEST | ERROR_NEEDS_SELF_TEST_PASSED, ..))
                if client_id.is_some() =>
            {
                self.conn.run_selftest(client_id.unwrap())?;
                self.conn
                    .login(UserId::TimeAdmin, self.time_admin_pin.as_str())?;
                self.conn.update_time(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                )?;
                self.retry_command(client_id, fun, max_trys - 1)
            }
            Err(TseError::CmdError(ERROR_NEEDS_ACTIVE_CTSS, ..)) => {
                self.conn.enable_ctss_interface()?;
                self.retry_command(client_id, fun, max_trys - 1)
            }
            Err(TseError::CmdError(ERROR_NOT_AUTHORIZED, ..)) => {
                self.conn
                    .login(UserId::TimeAdmin, self.time_admin_pin.as_str())?;
                self.retry_command(client_id, fun, max_trys - 1)
            }
            Err(TseError::CmdError(ERROR_NOT_INITIALIZED, ..)) => {
                self.conn.initialize()?;
                self.retry_command(client_id, fun, max_trys - 1)
            }
            r => r,
        }
    }
}
