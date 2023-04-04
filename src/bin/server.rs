extern crate clap;
extern crate core;



use clap::Parser;
use rouille::input::{basic_http_auth, json_input};
use rouille::Response;
use rouille::{Request, ResponseBody};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::fmt::{Debug};
use std::ops::Add;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use swissbit_tse::{Result, SignedTransaction, TransactionEvent, Tse, TseError, TseInfo, ERROR_CLIENT_NOT_REGISTERED};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Bind address of the rest interface
    #[arg(long, default_value = "0.0.0.0")]
    bind_address: String,

    /// Port of the rest interface
    #[arg(long, default_value_t = 80)]
    port: u16,

    /// Path to the TSE mountpoint
    #[arg(long, short = 't', long)]
    tse_path: String,

    /// Time Admin Pin of the TSE
    #[arg(long, short = 'p', long)]
    time_admin_pin: String,

    /// Admin Pin of the TSE
    #[arg(long, long)]
    admin_pin: Option<String>,

    /// Seconds after which a transaction should be canceled
    #[arg(long, default_value_t = 30 * 60)]
    transaction_timeout: u64,

    /// Allowed Clients "<client id>:<password for rest interface>"
    #[arg(short, long, required = true)]
    client: Vec<String>,
}

fn main() {
    let args = Args::parse();
    let client_ids: Vec<_> = args
        .client
        .iter()
        .map(|client_id_and_password| {
            if let Some(seperator_pos) = client_id_and_password.find(':') {
                client_id_and_password[..seperator_pos].to_string()
            } else {
                panic!("Could not parse client id / password, seperator missing")
            }
        })
        .collect();
    println!("Initializing connection with TSE");
    let (tse_state, tse_info) = State::init(
        args.tse_path,
        client_ids,
        args.time_admin_pin,
        args.admin_pin,
        Duration::from_secs(args.transaction_timeout),
    )
    .unwrap();
    println!("Connection with TSE initialized");

    let tse_state = Arc::new(Mutex::new(tse_state));
    let tse_info = Arc::new(tse_info);

    rouille::start_server((args.bind_address, args.port), move |request| {
        if let Some(credentials) = basic_http_auth(request) {
            if !args
                .client
                .contains(&format!("{}:{}", credentials.login, &credentials.password))
            {
                return Response::basic_http_auth_login_required("TSE");
            }

            rouille::router!(request,
                (GET) ["/information"] => {
                    Response::json(&*tse_info)
                },
                (POST) ["/transaction/start"] => {
                    handle_transaction_request(request, &tse_state, &credentials.login, None)
                },
                (POST) ["/transaction/{id}/finish", id: u64] => {
                   handle_transaction_request(request, &tse_state, &credentials.login, Some(id))
                },
                _ => Response::empty_404()
            )
        } else {
            Response::basic_http_auth_login_required("TSE")
        }
    });
}

fn handle_transaction_request(
    request: &Request,
    tse_state: &Mutex<State>,
    client_id: &str,
    transaction_id: Option<u64>,
) -> Response {
    if let Ok(body) = json_input::<SignTransactionRequest>(request) {
        if let Ok(mut tse_state) = tse_state.lock() {
            if let Ok(process_data) = STANDARD.decode(&body.process_data) {
                let transaction_result = if let Some(transaction_id) = transaction_id {
                    tse_state.finish_transaction(
                        client_id,
                        transaction_id,
                        &body.process_type,
                        &process_data,
                    )
                } else {
                    tse_state.start_transaction(client_id, &body.process_type, &process_data)
                };

                return match transaction_result {
                    Ok(signed_transaction) => {
                        let encoded_signed_transaction: EncodedSignedTransaction =
                            (&signed_transaction).into();
                        Response::json(&encoded_signed_transaction)
                    }
                    Err(err) => Response {
                        status_code: 500,
                        headers: vec![],
                        upgrade: None,
                        data: ResponseBody::from_string(format!(
                            "Could not process transaction {:?}",
                            err
                        )),
                    },
                };
            }
        } else {
            return Response {
                status_code: 500,
                headers: vec![],
                upgrade: None,
                data: ResponseBody::from_string("timeout"),
            };
        }
    }
    Response::empty_400()
}

struct TransactionState {
    timeout_time: Instant,
}

struct State {
    tse: Tse,
    transaction_states: HashMap<(String, u64), TransactionState>,
    transaction_timeout: Duration,
}

#[derive(Serialize)]
struct TseInformation {
    serial: String,
    signature_algorithm: &'static str,
    time_format: &'static str,
    process_data_encoding: &'static str,
    public_key: String,
    certificate: String,
}

#[derive(Serialize)]
pub struct EncodedSignedTransaction {
    pub transaction_id: u64,
    pub serial: String,
    pub log_time: u64,
    pub signature_counter: u64,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct SignTransactionRequest {
    process_type: String,
    process_data: String,
}

impl From<&SignedTransaction> for EncodedSignedTransaction {
    fn from(value: &SignedTransaction) -> Self {
        EncodedSignedTransaction {
            transaction_id: value.transaction_id,
            serial: STANDARD.encode(&value.serial),
            log_time: value.log_time,
            signature_counter: value.signature_counter,
            signature: STANDARD.encode(&value.signature),
        }
    }
}

impl State {
    fn init<P: AsRef<Path>>(
        path: P,
        client_ids: Vec<String>,
        time_admin_pin: String,
        admin_pin: Option<String>,
        transaction_timeout: Duration,
    ) -> Result<(Self, TseInformation)> {
        let mut tse = Tse::open(&path, time_admin_pin)?;

        let mut transaction_states = HashMap::new();
        for client_id in client_ids.iter() {
            match tse.list_started_transactions(client_id) {
                Ok(transactions) => {
                    for transaction in transactions {
                        transaction_states.insert(
                            (client_id.clone(), transaction),
                            TransactionState {
                                timeout_time: Instant::now().add(transaction_timeout),
                            },
                        );
                    }
                }
                Err(TseError::CmdError(ERROR_CLIENT_NOT_REGISTERED, ..)) => {
                    if let Some(admin_pin) = admin_pin.as_ref() {
                        tse.register_client(client_id, Some(admin_pin.as_str()))?;
                    } else {
                        //return Err("Could not register client - missing admin pin".to_string());
                    }
                }
                Err(e) => return Err(e),
            }
        }

        let tse_info = TseInfo::read(path)?;

        let certificate = tse.read_certificate()?;
        Ok((
            Self {
                tse,
                transaction_states,
                transaction_timeout,
            },
            TseInformation {
                signature_algorithm: "ecdsa-plain-SHA384",
                time_format: "unixTime",
                process_data_encoding: "UTF-8",
                serial: STANDARD.encode(tse_info.serial_number),
                certificate: String::from_utf8(certificate).unwrap(),
                public_key: STANDARD.encode(tse_info.public_key),
            },
        ))
    }

    fn start_transaction(
        &mut self,
        client_id: &str,
        process_type: &str,
        process_data: &[u8],
    ) -> Result<SignedTransaction> {
        let signed_transaction = self.tse.persist_transaction(
            client_id,
            TransactionEvent::Start,
            0,
            process_type,
            process_data,
        )?;
        self.transaction_states.insert(
            (client_id.to_string(), signed_transaction.transaction_id),
            TransactionState {
                timeout_time: Instant::now().add(self.transaction_timeout),
            },
        );
        Ok(signed_transaction)
    }

    fn finish_transaction(
        &mut self,
        client_id: &str,
        transaction_id: u64,
        process_type: &str,
        process_data: &[u8],
    ) -> Result<SignedTransaction> {
        let signed_transaction = self.tse.persist_transaction(
            client_id,
            TransactionEvent::Finish,
            transaction_id,
            process_type,
            process_data,
        )?;
        self.transaction_states
            .remove(&(client_id.to_string(), signed_transaction.transaction_id));
        Ok(signed_transaction)
    }

    fn finish_timedout_transactions(&mut self) {
        let now = Instant::now();

        self.transaction_states
            .retain(|(client_id, transaction_id), state| {
                if state.timeout_time < now {
                    if let Err(err) = self.tse.persist_transaction(
                        client_id,
                        TransactionEvent::Finish,
                        *transaction_id,
                        "SonstigerVorgang",
                        b"Timeout",
                    ) {
                        println!("Could not finish transaction {:?}", err);
                    }
                    false
                } else {
                    true
                }
            })
    }
}
