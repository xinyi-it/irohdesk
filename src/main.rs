#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use librustdesk::*;

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
fn main() {
    if !common::global_init() {
        eprintln!("Global initialization failed.");
        return;
    }
    common::test_rendezvous_server();
    common::test_nat_type();
    common::global_clean();
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "cli",
    feature = "flutter"
)))]
fn main() {
    #[cfg(all(windows, not(feature = "inline")))]
    unsafe {
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }
    if let Some(args) = crate::core_main::core_main().as_mut() {
        ui::start(args);
    }
    common::global_clean();
}

#[cfg(feature = "cli")]
fn main() {
    if !common::global_init() {
        return;
    }
    use hbb_common::log;
    use hbb_common::env_logger::*;
    init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));

    let args: Vec<String> = std::env::args().collect();

    // Simple arg parsing: --server, --get-iroh-id, --iroh-connect <id>, --password <pw>,
    // --port-forward <opts>, --connect <id>, --key <key>
    let mut server = false;
    let mut get_iroh_id = false;
    let mut iroh_connect: Option<String> = None;
    let mut password = String::new();
    let mut port_forward: Option<String> = None;
    let mut connect: Option<String> = None;
    let mut key = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => server = true,
            "--get-iroh-id" => get_iroh_id = true,
            "--iroh-connect" => {
                i += 1;
                if i < args.len() { iroh_connect = Some(args[i].clone()); }
            }
            "--password" => {
                i += 1;
                if i < args.len() { password = args[i].clone(); }
            }
            "--port-forward" | "-p" => {
                i += 1;
                if i < args.len() { port_forward = Some(args[i].clone()); }
            }
            "--connect" | "-c" => {
                i += 1;
                if i < args.len() { connect = Some(args[i].clone()); }
            }
            "--key" | "-k" => {
                i += 1;
                if i < args.len() { key = args[i].clone(); }
            }
            _ if args[i].starts_with("--iroh-connect=") => {
                iroh_connect = Some(args[i]["--iroh-connect=".len()..].to_owned());
            }
            _ if args[i].starts_with("--password=") => {
                password = args[i]["--password=".len()..].to_owned();
            }
            _ if args[i].starts_with("--port-forward=") => {
                port_forward = Some(args[i]["--port-forward=".len()..].to_owned());
            }
            _ if args[i].starts_with("--connect=") => {
                connect = Some(args[i]["--connect=".len()..].to_owned());
            }
            _ if args[i].starts_with("--key=") => {
                key = args[i]["--key=".len()..].to_owned();
            }
            _ => {}
        }
        i += 1;
    }

    use hbb_common::config::LocalConfig;

    if let Some(p) = port_forward {
        let options: Vec<String> = p.split(":").map(|x| x.to_owned()).collect();
        if options.len() < 3 {
            log::error!("Wrong port-forward options");
            return;
        }
        let mut port = 0;
        if let Ok(v) = options[1].parse::<i32>() {
            port = v;
        } else {
            log::error!("Wrong local-port");
            return;
        }
        let mut remote_port = 0;
        if let Ok(v) = options[2].parse::<i32>() {
            remote_port = v;
        } else {
            log::error!("Wrong remote-port");
            return;
        }
        let mut remote_host = "localhost".to_owned();
        if options.len() > 3 {
            remote_host = options[3].clone();
        }
        common::test_rendezvous_server();
        common::test_nat_type();
        let token = LocalConfig::get_option("access_token");
        cli::start_one_port_forward(
            options[0].clone(),
            port,
            remote_host,
            remote_port,
            key,
            token,
        );
    } else if let Some(p) = connect {
        common::test_rendezvous_server();
        common::test_nat_type();
        let token = LocalConfig::get_option("access_token");
        cli::connect_test(&p, key, token);
    } else if get_iroh_id {
        // Print Iroh NodeId for P2P direct connection
        match crate::iroh_transport::get_iroh_node_id() {
            Ok(id) => println!("{}", id),
            Err(e) => log::error!("Failed to get Iroh NodeId: {}", e),
        }
    } else if let Some(node_id) = iroh_connect {
        // P2P direct connection via Iroh - no hbbs needed
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            match crate::iroh_transport::iroh_connect_and_handshake(&node_id, &password).await {
                Ok(()) => {
                    log::info!("Iroh P2P session ended");
                }
                Err(e) => {
                    log::error!("Iroh P2P connection failed: {}", e);
                }
            }
        });
    } else if server {
        log::info!("id={}", hbb_common::config::Config::get_id());
        crate::start_server(true, false);
    }
    common::global_clean();
}
