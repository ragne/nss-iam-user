use rusoto_core::Region;
use rusoto_iam::{Iam, IamClient, ListGroupsRequest, ListUsersRequest, User, Group};



pub(crate) fn get_users(region: Region) -> Option<Vec<User>> {
  let client = IamClient::new(region);
  let request = ListUsersRequest {
    ..Default::default()
  };

  match client.list_users(request).sync() {
    Ok(output) => { Some(output.users) },
    Err(e) => { println!("Cannot get userlist, error: {}", e); None}
  }
}

pub(crate) fn get_groups(region: Region) -> Option<Vec<Group>> {
  let client = IamClient::new(region);
  let request = ListGroupsRequest {
    ..Default::default()
  };

  match client.list_groups(request).sync() {
    Ok(output) => { Some(output.groups) },
    Err(e) => { println!("Cannot get grouplist, error: {}", e); None}
  }
}


#[cfg(test)]
mod tests {
  use super::*;
    
    #[test]
    fn test_get_users() {
      let users = get_users(Region::UsEast1);
      assert!(users.is_some());
      println!("result is {:?}", users.unwrap());
    }

    #[test]
    fn test_get_groups() {
      let groups = get_groups(Region::UsEast1);
      assert!(groups.is_some());
      println!("result is {:?}", groups.unwrap());
    }
}