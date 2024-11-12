use std::{
    cell::RefCell, collections::HashMap, io::Cursor, rc::Rc, result::Result::{ Err, Ok }, sync::Arc, time::Duration
};

use chrono::{NaiveTime, Timelike, Utc};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use tokio::{runtime::Runtime, sync::Mutex};

use reqwest::{ClientBuilder, Url};
use serde_json::Value;
use anyhow::Result;
use crate::{decoder, encrypt::encrypt_data, json::{
    CourseInfo, 
    Node,
    TreeNode, UploadData
}};

const LOGIN_V2: &str = "https://sso.icve.com.cn/prod-api/data/userLoginV2";
const PASS_LOGIN: &str = "https://zjy2.icve.com.cn/prod-api/auth/passLogin?token=";
const RECORD_API: &str = "https://zjy2.icve.com.cn/prod-api/spoc/courseDesign/study/record?";
const COURSE_LIST: &str = "https://zjy2.icve.com.cn/prod-api/spoc/courseInfoStudent/myCourseList?pageNum=1&pageSize=999&isCriteria=1";
const GET_STUDY_CELLINFO: &str = "https://zjy2.icve.com.cn/prod-api/spoc/courseDesign/getStudyCellInfo?";
const UPLOAD: &str = "https://zjy2.icve.com.cn/prod-api/spoc/studyRecord/update";

lazy_static! {
    static ref RUNTIME: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(10)
        .enable_all()
        .build().unwrap();
}

pub struct Account {
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>
}

#[derive(Debug)]
pub struct Client {
    client: Arc<reqwest::Client>,
    pub token: Arc<String>,
    pub jwt: Arc<String>,
    pub class_list: HashMap<String, CourseInfo>,
    class_node: Option<Rc<RefCell<TreeNode>>>
}

impl Account {
    pub fn new_password(username: &str, password: &str) -> Self{
        Self {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            token: None
        }
    }
    pub fn new_token(token: &str) -> Self {
        Self {
            username: None,
            password: None,
            token: Some(token.to_string())
        }
    }
}

impl Client {
    pub async fn new(
        account: Account
    ) -> Result<Self> {
        let client = ClientBuilder::new()
            .gzip(true)
            .brotli(true)
            .zstd(true)
            .deflate(true)
            .cookie_store(true)
            .build()?;

        match account.token {
            Some(token) => {
                let jwt = get_jwt(&token, &client).await?;
                let class_list = get_class_list(&client, &token, &jwt).await?;
                
                Ok(Self {
                    client: Arc::new(client),
                    token: Arc::new(token),
                    jwt: Arc::new(jwt),
                    class_list,
                    class_node: None
                })
            },
            None => {
                let token = get_token(account.username.unwrap(), account.password.unwrap(), &client).await?;
                let jwt = get_jwt(&token, &client).await?;
                let class_list = get_class_list(&client, &token, &jwt).await?;

                Ok(Self {
                    client: Arc::new(client),
                    token: Arc::new(token),
                    jwt: Arc::new(jwt),
                    class_list,
                    class_node: None
                })
            }
        }
    }
    
    // 返回根节点，根节点data必定为None, 查询课程的返回结构与节点略有不同
    pub async fn get_class_node(&mut self, course_name: &str, class_id: &str) -> Result<Rc<RefCell<TreeNode>>> {
        let class = self.class_list.get(course_name).unwrap();
        // 节点深度，api需要
        let mut level = 1;
        let url = format!("{}courseId={}&courseInfoId={}&parentId={}&level={}&classId={}", RECORD_API, class.course_id, class.course_info_id, "0", level, class.class_id);
        level += 1;

        let node = self.client.get(url)
            .header("Cookie", format!("token={}; Token={}", self.token, self.jwt))
            .header("Authorization", format!("Bearer {}", self.jwt))
            .send().await?
            .json::<Vec<Node>>().await?;

        let mut root = TreeNode::default();
        
        for n in node {
            let temp = TreeNode::new(Some(n));
            root.append(temp);
        }

        let rc_root = Rc::new(RefCell::new(root));

        self.get_all_node(rc_root.clone(), level, class_id).await?;
        self.class_node = Some(rc_root.clone());

        Ok(rc_root)
    }

    pub async fn start_study(&mut self, course_name: &str) -> Result<()> {
        let class_id = &self.class_list[course_name].class_id.clone();

        self.get_class_node(course_name, class_id).await?;
        
        let mut handles = Vec::new();
        let multi_bars = MultiProgress::new();

        for node in self.class_node.take().unwrap().take().iter() {
            let study_data = self.get_study_record(class_id, &node.id).await?;
            //let bar = ProgressBar::new((study_data.total_num / 5).try_into().unwrap());
            //multi_bars.add(bar.clone());
            
            //println!("node Type = {}", node.file_type);
            let bar = ProgressBar::new(study_data.total_num.into());
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")?
                    .progress_chars("=> ")
            );
            //let bar = ProgressBar::new(study_data.total_num.try_into().unwrap());
            multi_bars.add(bar.clone());
            // println!("{:?}", study_data);
            
            /*if node.file_type != "img" {
                continue;
            }*/
            //println!("name = {}", node.name);

            if study_data.actual_num == study_data.total_num {
                continue;
            }

            let study_data = Arc::new(Mutex::new(study_data));
            let client = self.client.clone();
            let token = self.token.clone();
            let jwt = self.jwt.clone();
            let name = node.name;

            bar.set_message(name.clone());

            let handle = RUNTIME.spawn(async move {
                let mut study_lock = study_data.lock().await;
                study_lock.study_time = 5;
                
                bar.inc(study_lock.actual_num.into());
                let mut count = 0;

                for i in study_lock.actual_num..study_lock.total_num {
                    count += 1;
                    if count >= 4 {
                        count = 0;
            
                        study_lock.actual_num = i;
                        study_lock.last_num = i;
                        upload_data(&client, &token, &jwt, &study_lock).await.unwrap();
                    }

                    tokio::time::sleep(Duration::new(1, 0)).await;
                    //study_lock.last_num = i;
                    bar.inc(1);
                }
                
                if count != 0 {
                    study_lock.actual_num = study_lock.total_num;
                    study_lock.last_num = study_lock.total_num;

                    let _ = upload_data(&client, &token, &jwt, &study_lock).await; 
                }
               
                bar.finish_with_message(format!("节点 {} 完成", name));
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(_) => { continue },
                Err(err)  => {
                    println!("{:?}", err.try_into_panic());
                }
            }
        }

        Ok(())
    }

    async fn get_study_record(&self, class_id: &str, node_id: &str) -> Result<UploadData> {
        let url = format!("{}id={}&classId={}", GET_STUDY_CELLINFO, node_id, class_id);

        let mut res = self.client.get(url)
            .header("Cookie", format!("token={}; Token={}", self.token, self.jwt))
            .header("Authorization", format!("Bearer {}", self.jwt))
            .send().await?
            .json::<Value>().await?;
        
        let study_record = res["data"]["studentStudyRecord"].take();
        // println!("{}", res["data"]["fileType"].as_str().unwrap());
        match serde_json::from_value(study_record) {
            Ok(data) => { return Ok(data) },
            Err(_) => {
                let file_url = res["data"]["fileUrl"].as_str().unwrap();
                let file: Value = serde_json::from_str(file_url)?;
                let file_url = file["url"].as_str().unwrap();
                let file_type = res["data"]["fileType"].as_str().unwrap();
                
                let mut total_num: u32 = 0;
                if file_type == "ppt" || file_type == "pdf" || file_type == "doc" {
                    let url = Url::parse_with_params("https://zjy2.icve.com.cn/prod-api/spoc/oss/getUrlPngs", &[("fileUrl", file_url)])?;

                    //println!("{}", file_type);

                    let file_res = self.client.get(url)
                        .header("Cookie", format!("token={}; Token={}", self.token, self.jwt))
                        .header("Authorization", format!("Bearer {}", self.jwt))
                        .json(&["fileUrl", file_url])
                        .send().await?
                        .json::<Value>().await?;
                    
                    let pngs = file_res["data"].as_array().unwrap();
                    total_num = pngs.len().try_into().unwrap();
                } else if file_type == "img" || file_type == "图文" {
                    total_num = 1;
                } else if file_type == "video" {
                    let utc = Utc::now();
                    let time = utc.timestamp_millis() + 28800;
                    let file_url = Url::parse(format!("https://upload.icve.com.cn/{}/status?time={}&token=5958F068E52BCF92A7B330AD3565BF10", file_url, time).as_str())?;
                    
                    let video_res = self.client.get(file_url)
                        .send().await?
                        .json::<Value>().await?;

                    let video_time = video_res["args"]["duration"].as_str().unwrap();
                    total_num = NaiveTime::parse_from_str(&video_time[..8], "%H:%M:%S").unwrap().num_seconds_from_midnight().try_into()?;
                } else if file_type == "audio" {
                    let file_json: Value = serde_json::from_str(res["data"]["fileUrl"].as_str().unwrap())?;
                    let file_url = file_json["ossOriUrl"].as_str().unwrap();

                    let stream = self.client.get(file_url)
                        .header("Cookie", format!("token={}", self.token))
                        .send().await?
                        .bytes().await?
                        .to_vec();

                    total_num = decoder::get_audio_length(Cursor::new(stream)).try_into()?;
                } 
    
                return Ok(UploadData {
                    course_info_id: res["data"]["courseInfoId"].as_str().unwrap().to_string(),
                    class_id: class_id.to_string(),
                    study_time: 1,
                    source_id: res["data"]["id"].as_str().unwrap().to_string(),
                    total_num,
                    actual_num: 0,
                    last_num: 0
                });
            }
        };
    } 

    /* 
    * 根据传入节点获取此节点下所有节点
    * root: 根节点
    * level: 传入的节点深度
    * class_id: 根课程id而非节点id
    */
    async fn get_all_node(&self, root: Rc<RefCell<TreeNode>>, level: i32, class_id: &str) -> Result<()> {
        let current = root.borrow();
        let mut stack: Vec<Rc<RefCell<TreeNode>>> = Vec::new();

        for n in &current.node {
            stack.push(n.clone());
        }
        let mut level = level;

        loop {
            if stack.is_empty() {
                break;
            }
            let mut temp: Vec<Rc<RefCell<TreeNode>>> = Vec::new();
            // 假设父节点为root, n则是树的下一层的一个叶子
            for n in &mut stack {
                // 为这个节点添加它的值和子节点
                let mut mut_node = n.borrow_mut();
                let class_data = mut_node.data.clone().unwrap();
                // 处理这个节点，然后将这个节点的子节点创建一个指针塞到这个节点的node,
                let course_info_id = if let Some(id) = class_data.course_info_id { id } else { "0".to_string() };

                let url = format!("{}courseId={}&courseInfoId={}&parentId={}&level={}&classId={}", RECORD_API, class_data.course_id, course_info_id, class_data.id, level, class_id);
                
                let next_node = self.client.get(url)
                    .header("Cookie", format!("token={}; Token={}", self.token, self.jwt))
                    .header("Authorization", format!("Bearer {}", self.jwt))
                    .send().await?
                    .json::<Vec<Node>>().await?;
                
                if next_node.is_empty() {
                    continue;
                }

                for next in next_node {
                    let temp_node = TreeNode::new(Some(next));

                    mut_node.append(temp_node);
                }

                for node in &mut_node.node {
                    temp.push(node.clone());
                }
            }
            // stack.clear();
            stack = Vec::from(temp);
            
            level += 1;
        }
        Ok(())
    }
}
async fn upload_data(client: &reqwest::Client, token: &str, jwt: &str, data: &UploadData) -> Result<()> {
    //println!("{}", serde_json::to_string_pretty(data).unwrap());
    let body = format!(r#"{{"param":"{}"}}"#, encrypt_data(data, jwt));
    //println!("{}", body);
    //let form = multipart::Form::new().text("param", encrypt_data(data, &jwt).as_str());
    let res = client.post(UPLOAD)
        .header("Cookie", format!("token={}; Token={}; Admin-Expires-In=10080", token, jwt))
        .header("Authorization", format!("Bearer {}", jwt))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        //.json(&["param", &encrypt_data(data, &jwt)])
        .body(body)
        .send().await?;

    // println!("{}", res.text().await?);

    Ok(())
}
async fn get_token(username: String, password: String, client: &reqwest::Client) -> Result<String> {
    let mut json: HashMap<&str, Value> = HashMap::new();
                
    json.insert("userName", serde_json::to_value(username)?);
    json.insert("password", serde_json::to_value(password)?);
    json.insert("type", serde_json::to_value(1)?);
    json.insert("webPageSource", serde_json::to_value(1)?);

    let res = client.post(LOGIN_V2)
        .json(&json)
        .send().await?
        .json::<Value>().await?;
    Ok(res.get("data").unwrap()
        .get("token").unwrap()
        .as_str().unwrap().to_string())
}

async fn get_jwt(token: &String, client: &reqwest::Client) -> Result<String> {
    let res = client.get(format!("{}{}", PASS_LOGIN, token))
                    .header("Accept", "application/json")
                    .send().await?
                    .json::<Value>().await?;
    
    Ok(res.get("data").unwrap()
        .get("access_token").unwrap()
        .as_str().unwrap().to_string())
}

async fn get_class_list(client: &reqwest::Client, token: &str, jwt: &str) -> Result<HashMap<String, CourseInfo>> {
    let mut res = client.get(COURSE_LIST)
        .header("Accept", "application/json")
        .header("Cookie", format!("token={}; Token={}", token, jwt))
        .header("Authorization", format!("Bearer {}", jwt))
        .send().await?
        .json::<Value>().await?;

    let data: Vec<CourseInfo> = serde_json::from_value(res["rows"].take())?;
    let mut map: HashMap<String, CourseInfo> = HashMap::new();

    for d in data {
        map.insert(d.course_name.clone(), d);
    }

    Ok(map)
}
