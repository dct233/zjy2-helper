use std::{cell::RefCell, rc::Rc};

use serde::{
    Serialize,
    Deserialize
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadData {
    pub course_info_id: String,
    pub class_id: String,
    pub study_time: u32,
    pub source_id: String,
    pub total_num: u32,
    pub actual_num: u32,
    pub last_num: u32
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CourseInfo {
    pub id: String,
    pub course_id: String,
    pub course_info_id: String,
    pub class_id: String,
    pub term_id: String,
    pub class_name: String,
    pub course_name: String,
    pub is_criteria: i32,
    //#[serde(skip)]
    //pub class_node: TreeNode
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub data: Option<Node>,
    pub node: Vec<Rc<RefCell<TreeNode>>>
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    pub course_id: String,
    pub course_info_id: Option<String>,
    pub design_id: Option<String>,
    pub parent_id: Option<String>,
    pub topic_id: Option<String>,
    pub name: String,
    pub level: Option<String>,
    pub children: Option<Vec<Node>>,
    pub file_type: String,
}

impl TreeNode {
    pub fn new(data: Option<Node>) -> Self {
        Self {
            data,
            node: vec![]
        }
    }

    pub fn rc_new(node: Vec<Rc<RefCell<TreeNode>>>) -> Self {
        Self {
            data: None,
            node
        }
    }

    pub fn append(&mut self, node: TreeNode) {
        self.node.push(Rc::new(RefCell::new(node)));
    }

    pub fn iter(self) -> TreeNodeIter {
        TreeNodeIter::new(vec![Rc::new(RefCell::new(self))])
    }
}

impl Default for TreeNode {
    fn default() -> Self {
        Self {
            data: None,
            node: vec![]
        }
    }
}

pub struct TreeNodeIter {
    stack: Vec<Rc<RefCell<TreeNode>>>
}

impl TreeNodeIter {
    pub fn new(tree: Vec<Rc<RefCell<TreeNode>>>) -> Self {
        Self {
            stack: tree 
        }
    }
}

impl Iterator for TreeNodeIter {
    type Item = Node;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            self.stack.extend(node.borrow().node.clone());
            if let Some(data) = &node.borrow().data { 
                if data.file_type == "父节点" || data.file_type == "子节点" || data.file_type == "作业" {
                    continue;
                } else if data.file_type == "文件夹" {
                    for child in data.children.clone().unwrap() {
                        self.stack.push(Rc::new(RefCell::new(TreeNode::new(Some(child)))));
                    }
                    continue;
                }
                return Some(data.clone())
            }
        }
        None
    }
}
