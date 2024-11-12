use std::{env, io::{self, Write}};
use anyhow::Ok;
use client::{Account, Client};

mod encrypt;
mod json;
mod client;
mod decoder;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = args[1].as_str();

    let account = match command {
        "password" => {
            let username = &args[2];
            let password = &args[3];

            Account::new_password(username, password)
        },
        "token" => {
            let token = &args[2];

            Account::new_token(token)
        },
        _ => {
            panic!("意料之外的参数")
        }
    };
    let mut client = Client::new(account).await?;
    let range: Vec<String> = client.class_list.clone().into_keys().collect();

    if let Some(course_name) = args.get(4) {
        client.start_study(course_name).await?;
    } else {
        for i in 0..range.len() {
            println!("{}. {}", i, range[i]);
        }
        print!("选择刷取的课程(可多选): ");
        let _ = std::io::stdout().flush();

        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).expect("没有选择数据");
        let switch: Vec<usize> = buffer.split("").filter_map(|num| num.parse::<usize>().ok()).collect();
                
        for i in switch {
            println!("{}", i);
            println!("{}", &range[i]);
            client.start_study(&range[i]).await?;
        }
    }
    //t.start_study("91bb2209d95d406b8509add55d7752ff_mi").await?;

    //let node = t.get_class_node("3527C361-21B0-4743-B8FE-4DBD92EE9331").await?;
    
    //let rc_node = node.borrow();
    //println!("{:?}", rc_node);

    //for n in rc_node.clone().iter() {
    //    println!("{:?}", n);
    //}

    Ok(()) 
}
