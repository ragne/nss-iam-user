/// AWS IAM handpicked structs for performing requests to IAM. Based on rusoto-IAM
/// The main motivation is to get rid of all the structs we aren't using, but they're still got linked into dylib
/// anyway.
use std::error::Error;
use std::fmt;

#[allow(warnings)]
use futures::future;
use futures::Future;
use rusoto_core::credential::ProvideAwsCredentials;
use rusoto_core::region;
use rusoto_core::request::{BufferedHttpResponse, DispatchSignedRequest};
use rusoto_core::{Client, RusotoError, RusotoFuture};

use rusoto_core::param::{Params, ServiceParams};
use rusoto_core::proto::xml::error::*;
use rusoto_core::proto::xml::util::{
    characters, deserialize_elements, end_element, find_start_element, peek_at_name, skip_tree,
    start_element,
};
use rusoto_core::proto::xml::util::{Next, Peek, XmlParseError, XmlResponse};
use rusoto_core::signature::SignedRequest;
use serde_urlencoded;
use std::str::FromStr;
use xml::reader::ParserConfig;
use xml::EventReader;

/// <p>A structure that represents user-provided metadata that can be associated with a resource such as an IAM user or role. For more information about tagging, see <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM Identities</a> in the <i>IAM User Guide</i>.</p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Tag {
    /// <p>The key name that can be used to look up or retrieve the associated value. For example, <code>Department</code> or <code>Cost Center</code> are common choices.</p>
    pub key: String,
    /// <p><p>The value associated with this tag. For example, tags with a key name of <code>Department</code> could have values such as <code>Human Resources</code>, <code>Accounting</code>, and <code>Support</code>. Tags with a key name of <code>Cost Center</code> might have values that consist of the number associated with the different cost centers in your company. Typically, many resources have tags with the same key name but with different values.</p> <note> <p>AWS always interprets the tag <code>Value</code> as a single string. If you need to store an array, you can store comma-separated values in the string. However, you must interpret the value in your code.</p> </note></p>
    pub value: String,
}

struct TagDeserializer;
impl TagDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<Tag, XmlParseError> {
        deserialize_elements::<_, Tag, _>(tag_name, stack, |name, stack, obj| {
            match name {
                "Key" => {
                    obj.key = StringTypeDeserializer::deserialize("Key", stack)?;
                }
                "Value" => {
                    obj.value = StringTypeDeserializer::deserialize("Value", stack)?;
                }
                _ => skip_tree(stack),
            }
            Ok(())
        })
    }
}

struct TagListTypeDeserializer;
impl TagListTypeDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<Vec<Tag>, XmlParseError> {
        deserialize_elements::<_, Vec<_>, _>(tag_name, stack, |name, stack, obj| {
            if name == "member" {
                obj.push(TagDeserializer::deserialize("member", stack)?);
            } else {
                skip_tree(stack);
            }
            Ok(())
        })
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct ListSSHPublicKeysRequest {
    /// <p>Use this parameter only when paginating results and only after you receive a response indicating that the results are truncated. Set it to the value of the <code>Marker</code> element in the response that you received to indicate where the next call should start.</p>
    pub marker: Option<String>,
    /// <p>Use this only when paginating results to indicate the maximum number of items you want in the response. If additional items exist beyond the maximum you specify, the <code>IsTruncated</code> response element is <code>true</code>.</p> <p>If you do not include this parameter, the number of items defaults to 100. Note that IAM might return fewer results, even when there are more results available. In that case, the <code>IsTruncated</code> response element returns <code>true</code>, and <code>Marker</code> contains a value to include in the subsequent call that tells the service where to continue from.</p>
    pub max_items: Option<i64>,
    /// <p>The name of the IAM user to list SSH public keys for. If none is specified, the <code>UserName</code> field is determined implicitly based on the AWS access key used to sign the request.</p> <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub user_name: Option<String>,
}

/// Serialize `ListSSHPublicKeysRequest` contents to a `SignedRequest`.
struct ListSSHPublicKeysRequestSerializer;
impl ListSSHPublicKeysRequestSerializer {
    fn serialize(params: &mut Params, name: &str, obj: &ListSSHPublicKeysRequest) {
        let mut prefix = name.to_string();
        if prefix != "" {
            prefix.push_str(".");
        }

        if let Some(ref field_value) = obj.marker {
            params.put(&format!("{}{}", prefix, "Marker"), &field_value);
        }
        if let Some(ref field_value) = obj.max_items {
            params.put(&format!("{}{}", prefix, "MaxItems"), &field_value);
        }
        if let Some(ref field_value) = obj.user_name {
            params.put(&format!("{}{}", prefix, "UserName"), &field_value);
        }
    }
}

/// <p>Contains the response to a successful <a>ListSSHPublicKeys</a> request.</p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct ListSSHPublicKeysResponse {
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub is_truncated: Option<bool>,
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub marker: Option<String>,
    /// <p>A list of the SSH public keys assigned to IAM user.</p>
    pub ssh_public_keys: Option<Vec<SSHPublicKeyMetadata>>,
}

struct BooleanTypeDeserializer;
impl BooleanTypeDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<bool, XmlParseError> {
        start_element(tag_name, stack)?;
        let obj = bool::from_str(characters(stack)?.as_ref()).unwrap();
        end_element(tag_name, stack)?;

        Ok(obj)
    }
}

struct StringTypeDeserializer;
impl StringTypeDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<String, XmlParseError> {
        start_element(tag_name, stack)?;
        let obj = characters(stack)?;
        end_element(tag_name, stack)?;

        Ok(obj)
    }
}

/// <p>Contains information about an SSH public key, without the key's body or fingerprint.</p> <p>This data type is used as a response element in the <a>ListSSHPublicKeys</a> operation.</p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct SSHPublicKeyMetadata {
    /// <p>The unique identifier for the SSH public key.</p>
    pub ssh_public_key_id: String,
    /// <p>The status of the SSH public key. <code>Active</code> means that the key can be used for authentication with an AWS CodeCommit repository. <code>Inactive</code> means that the key cannot be used.</p>
    pub status: String,
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the SSH public key was uploaded.</p>
    pub upload_date: String,
    /// <p>The name of the IAM user associated with the SSH public key.</p>
    pub user_name: String,
}

struct SSHPublicKeyMetadataDeserializer;
impl SSHPublicKeyMetadataDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<SSHPublicKeyMetadata, XmlParseError> {
        deserialize_elements::<_, SSHPublicKeyMetadata, _>(tag_name, stack, |name, stack, obj| {
            match name {
                "SSHPublicKeyId" => {
                    obj.ssh_public_key_id =
                        StringTypeDeserializer::deserialize("SSHPublicKeyId", stack)?;
                }
                "Status" => {
                    obj.status = StringTypeDeserializer::deserialize("Status", stack)?;
                }
                "UploadDate" => {
                    obj.upload_date = StringTypeDeserializer::deserialize("UploadDate", stack)?;
                }
                "UserName" => {
                    obj.user_name = StringTypeDeserializer::deserialize("UserName", stack)?;
                }
                _ => skip_tree(stack),
            }
            Ok(())
        })
    }
}

struct SSHPublicKeyListTypeDeserializer;
impl SSHPublicKeyListTypeDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<Vec<SSHPublicKeyMetadata>, XmlParseError> {
        deserialize_elements::<_, Vec<_>, _>(tag_name, stack, |name, stack, obj| {
            if name == "member" {
                obj.push(SSHPublicKeyMetadataDeserializer::deserialize(
                    "member", stack,
                )?);
            } else {
                skip_tree(stack);
            }
            Ok(())
        })
    }
}

struct UserListTypeDeserializer;
impl UserListTypeDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<Vec<User>, XmlParseError> {
        deserialize_elements::<_, Vec<_>, _>(tag_name, stack, |name, stack, obj| {
            if name == "member" {
                obj.push(UserDeserializer::deserialize("member", stack)?);
            } else {
                skip_tree(stack);
            }
            Ok(())
        })
    }
}

/// <p><p>Contains information about an IAM user entity.</p> <p>This data type is used as a response element in the following operations:</p> <ul> <li> <p> <a>CreateUser</a> </p> </li> <li> <p> <a>GetUser</a> </p> </li> <li> <p> <a>ListUsers</a> </p> </li> </ul></p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct User {
    /// <p>The Amazon Resource Name (ARN) that identifies the user. For more information about ARNs and how to use ARNs in policies, see <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM Identifiers</a> in the <i>Using IAM</i> guide. </p>
    pub arn: String,
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the user was created.</p>
    pub create_date: String,
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the user's password was last used to sign in to an AWS website. For a list of AWS websites that capture a user's last sign-in time, see the <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/credential-reports.html">Credential Reports</a> topic in the <i>Using IAM</i> guide. If a password is used more than once in a five-minute span, only the first use is returned in this field. If the field is null (no value), then it indicates that they never signed in with a password. This can be because:</p> <ul> <li> <p>The user never had a password.</p> </li> <li> <p>A password exists but has not been used since IAM started tracking this information on October 20, 2014.</p> </li> </ul> <p>A null valuedoes not mean that the user <i>never</i> had a password. Also, if the user does not currently have a password, but had one in the past, then this field contains the date and time the most recent password was used.</p> <p>This value is returned only in the <a>GetUser</a> and <a>ListUsers</a> operations. </p>
    pub password_last_used: Option<String>,
    /// <p>The path to the user. For more information about paths, see <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM Identifiers</a> in the <i>Using IAM</i> guide.</p>
    pub path: String,
    /// <p>The ARN of the policy used to set the permissions boundary for the user.</p> <p>For more information about permissions boundaries, see <a href="IAM/latest/UserGuide/access_policies_boundaries.html">Permissions Boundaries for IAM Identities </a> in the <i>IAM User Guide</i>.</p>
    pub permissions_boundary: Option<String>,
    /// <p>A list of tags that are associated with the specified user. For more information about tagging, see <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM Identities</a> in the <i>IAM User Guide</i>.</p>
    pub tags: Option<Vec<Tag>>,
    /// <p>The stable and unique string identifying the user. For more information about IDs, see <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM Identifiers</a> in the <i>Using IAM</i> guide.</p>
    pub user_id: String,
    /// <p>The friendly name identifying the user.</p>
    pub user_name: String,
}

struct UserDeserializer;
impl UserDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<User, XmlParseError> {
        deserialize_elements::<_, User, _>(tag_name, stack, |name, stack, obj| {
            match name {
                "Arn" => {
                    obj.arn = StringTypeDeserializer::deserialize("Arn", stack)?;
                }
                "CreateDate" => {
                    obj.create_date = StringTypeDeserializer::deserialize("CreateDate", stack)?;
                }
                "PasswordLastUsed" => {
                    obj.password_last_used = Some(StringTypeDeserializer::deserialize(
                        "PasswordLastUsed",
                        stack,
                    )?);
                }
                "Path" => {
                    obj.path = StringTypeDeserializer::deserialize("Path", stack)?;
                }
                "PermissionsBoundary" => {
                    obj.permissions_boundary = None; // just ignore
                }
                "Tags" => {
                    obj.tags
                        .get_or_insert(vec![])
                        .extend(TagListTypeDeserializer::deserialize("Tags", stack)?);
                }
                "UserId" => {
                    obj.user_id = StringTypeDeserializer::deserialize("UserId", stack)?;
                }
                "UserName" => {
                    obj.user_name = StringTypeDeserializer::deserialize("UserName", stack)?;
                }
                _ => skip_tree(stack),
            }
            Ok(())
        })
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct ListUsersRequest {
    /// <p>Use this parameter only when paginating results and only after you receive a response indicating that the results are truncated. Set it to the value of the <code>Marker</code> element in the response that you received to indicate where the next call should start.</p>
    pub marker: Option<String>,
    /// <p>Use this only when paginating results to indicate the maximum number of items you want in the response. If additional items exist beyond the maximum you specify, the <code>IsTruncated</code> response element is <code>true</code>.</p> <p>If you do not include this parameter, the number of items defaults to 100. Note that IAM might return fewer results, even when there are more results available. In that case, the <code>IsTruncated</code> response element returns <code>true</code>, and <code>Marker</code> contains a value to include in the subsequent call that tells the service where to continue from.</p>
    pub max_items: Option<i64>,
    /// <p> The path prefix for filtering the results. For example: <code>/division_abc/subdivision_xyz/</code>, which would get all user names whose path starts with <code>/division_abc/subdivision_xyz/</code>.</p> <p>This parameter is optional. If it is not included, it defaults to a slash (/), listing all user names. This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of either a forward slash (/) by itself or a string that must begin and end with forward slashes. In addition, it can contain any ASCII character from the ! (\u0021) through the DEL character (\u007F), including most punctuation characters, digits, and upper and lowercased letters.</p>
    pub path_prefix: Option<String>,
}

/// Serialize `ListUsersRequest` contents to a `SignedRequest`.
struct ListUsersRequestSerializer;
impl ListUsersRequestSerializer {
    fn serialize(params: &mut Params, name: &str, obj: &ListUsersRequest) {
        let mut prefix = name.to_string();
        if prefix != "" {
            prefix.push_str(".");
        }

        if let Some(ref field_value) = obj.marker {
            params.put(&format!("{}{}", prefix, "Marker"), &field_value);
        }
        if let Some(ref field_value) = obj.max_items {
            params.put(&format!("{}{}", prefix, "MaxItems"), &field_value);
        }
        if let Some(ref field_value) = obj.path_prefix {
            params.put(&format!("{}{}", prefix, "PathPrefix"), &field_value);
        }
    }
}

/// <p>Contains information about an SSH public key.</p> <p>This data type is used as a response element in the <a>GetSSHPublicKey</a> and <a>UploadSSHPublicKey</a> operations. </p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct SSHPublicKey {
    /// <p>The MD5 message digest of the SSH public key.</p>
    pub fingerprint: String,
    /// <p>The SSH public key.</p>
    pub ssh_public_key_body: String,
    /// <p>The unique identifier for the SSH public key.</p>
    pub ssh_public_key_id: String,
    /// <p>The status of the SSH public key. <code>Active</code> means that the key can be used for authentication with an AWS CodeCommit repository. <code>Inactive</code> means that the key cannot be used.</p>
    pub status: String,
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the SSH public key was uploaded.</p>
    pub upload_date: Option<String>,
    /// <p>The name of the IAM user associated with the SSH public key.</p>
    pub user_name: String,
}

struct SSHPublicKeyDeserializer;
impl SSHPublicKeyDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<SSHPublicKey, XmlParseError> {
        deserialize_elements::<_, SSHPublicKey, _>(tag_name, stack, |name, stack, obj| {
            match name {
                "Fingerprint" => {
                    obj.fingerprint = StringTypeDeserializer::deserialize("Fingerprint", stack)?;
                }
                "SSHPublicKeyBody" => {
                    obj.ssh_public_key_body =
                        StringTypeDeserializer::deserialize("SSHPublicKeyBody", stack)?;
                }
                "SSHPublicKeyId" => {
                    obj.ssh_public_key_id =
                        StringTypeDeserializer::deserialize("SSHPublicKeyId", stack)?;
                }
                "Status" => {
                    obj.status = StringTypeDeserializer::deserialize("Status", stack)?;
                }
                "UploadDate" => {
                    obj.upload_date =
                        Some(StringTypeDeserializer::deserialize("UploadDate", stack)?);
                }
                "UserName" => {
                    obj.user_name = StringTypeDeserializer::deserialize("UserName", stack)?;
                }
                _ => skip_tree(stack),
            }
            Ok(())
        })
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct GetSSHPublicKeyRequest {
    /// <p>Specifies the public key encoding format to use in the response. To retrieve the public key in ssh-rsa format, use <code>SSH</code>. To retrieve the public key in PEM format, use <code>PEM</code>.</p>
    pub encoding: String,
    /// <p>The unique identifier for the SSH public key.</p> <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters that can consist of any upper or lowercased letter or digit.</p>
    pub ssh_public_key_id: String,
    /// <p>The name of the IAM user associated with the SSH public key.</p> <p>This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub user_name: String,
}

/// Serialize `GetSSHPublicKeyRequest` contents to a `SignedRequest`.
struct GetSSHPublicKeyRequestSerializer;
impl GetSSHPublicKeyRequestSerializer {
    fn serialize(params: &mut Params, name: &str, obj: &GetSSHPublicKeyRequest) {
        let mut prefix = name.to_string();
        if prefix != "" {
            prefix.push_str(".");
        }

        params.put(&format!("{}{}", prefix, "Encoding"), &obj.encoding);
        params.put(
            &format!("{}{}", prefix, "SSHPublicKeyId"),
            &obj.ssh_public_key_id,
        );
        params.put(&format!("{}{}", prefix, "UserName"), &obj.user_name);
    }
}

/// <p>Contains the response to a successful <a>GetSSHPublicKey</a> request.</p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct GetSSHPublicKeyResponse {
    /// <p>A structure containing details about the SSH public key.</p>
    pub ssh_public_key: Option<SSHPublicKey>,
}

struct GetSSHPublicKeyResponseDeserializer;
impl GetSSHPublicKeyResponseDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<GetSSHPublicKeyResponse, XmlParseError> {
        deserialize_elements::<_, GetSSHPublicKeyResponse, _>(
            tag_name,
            stack,
            |name, stack, obj| {
                match name {
                    "SSHPublicKey" => {
                        obj.ssh_public_key = Some(SSHPublicKeyDeserializer::deserialize(
                            "SSHPublicKey",
                            stack,
                        )?);
                    }
                    _ => skip_tree(stack),
                }
                Ok(())
            },
        )
    }
}

/// <p>Contains the response to a successful <a>ListUsers</a> request. </p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct ListUsersResponse {
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub is_truncated: Option<bool>,
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub marker: Option<String>,
    /// <p>A list of users.</p>
    pub users: Vec<User>,
}

struct ListSSHPublicKeysResponseDeserializer;
impl ListSSHPublicKeysResponseDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<ListSSHPublicKeysResponse, XmlParseError> {
        deserialize_elements::<_, ListSSHPublicKeysResponse, _>(
            tag_name,
            stack,
            |name, stack, obj| {
                match name {
                    "IsTruncated" => {
                        obj.is_truncated =
                            Some(BooleanTypeDeserializer::deserialize("IsTruncated", stack)?);
                    }
                    "Marker" => {
                        obj.marker = Some(StringTypeDeserializer::deserialize("Marker", stack)?);
                    }
                    "SSHPublicKeys" => {
                        obj.ssh_public_keys.get_or_insert(vec![]).extend(
                            SSHPublicKeyListTypeDeserializer::deserialize("SSHPublicKeys", stack)?,
                        );
                    }
                    _ => skip_tree(stack),
                }
                Ok(())
            },
        )
    }
}

/// Errors returned by ListSSHPublicKeys
#[derive(Debug, PartialEq)]
pub enum ListSSHPublicKeysError {
    /// <p>The request was rejected because it referenced a resource entity that does not exist. The error message describes the resource.</p>
    NoSuchEntity(String),
    ServiceFailure(String),
    UnrecognizedPublicKeyEncoding(String),
}

impl ListSSHPublicKeysError {
    pub fn from_response(res: BufferedHttpResponse) -> RusotoError<ListSSHPublicKeysError> {
        {
            let reader = EventReader::new(res.body.as_ref());
            let mut stack = XmlResponse::new(reader.into_iter().peekable());
            find_start_element(&mut stack);
            if let Ok(parsed_error) = Self::deserialize(&mut stack) {
                match &parsed_error.code[..] {
                    "NoSuchEntity" => {
                        return RusotoError::Service(ListSSHPublicKeysError::NoSuchEntity(
                            String::from(parsed_error.message),
                        ))
                    }
                    "ServiceFailure" => {
                        return RusotoError::Service(ListSSHPublicKeysError::ServiceFailure(
                            String::from(parsed_error.message),
                        ))
                    }
                    "UnrecognizedPublicKeyEncoding" => {
                        return RusotoError::Service(
                            ListSSHPublicKeysError::UnrecognizedPublicKeyEncoding(String::from(
                                parsed_error.message,
                            )),
                        )
                    }
                    _ => {}
                }
            }
        }
        RusotoError::Unknown(res)
    }

    fn deserialize<T>(stack: &mut T) -> Result<XmlError, XmlParseError>
    where
        T: Peek + Next,
    {
        start_element("ErrorResponse", stack)?;
        XmlErrorDeserializer::deserialize("Error", stack)
    }
}
impl fmt::Display for ListSSHPublicKeysError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}
impl Error for ListSSHPublicKeysError {
    fn description(&self) -> &str {
        match *self {
            ListSSHPublicKeysError::NoSuchEntity(ref cause) => cause,
            ListSSHPublicKeysError::ServiceFailure(ref cause) => cause,
            ListSSHPublicKeysError::UnrecognizedPublicKeyEncoding(ref cause) => cause,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct GetUserRequest {
    /// <p>The name of the user to get information about.</p> <p>This parameter is optional. If it is not included, it defaults to the user making the request. This parameter allows (through its <a href="http://wikipedia.org/wiki/regex">regex pattern</a>) a string of characters consisting of upper and lowercase alphanumeric characters with no spaces. You can also include any of the following characters: _+=,.@-</p>
    pub user_name: Option<String>,
}

/// Serialize `GetUserRequest` contents to a `SignedRequest`.
struct GetUserRequestSerializer;
impl GetUserRequestSerializer {
    fn serialize(params: &mut Params, name: &str, obj: &GetUserRequest) {
        let mut prefix = name.to_string();
        if prefix != "" {
            prefix.push_str(".");
        }

        if let Some(ref field_value) = obj.user_name {
            params.put(&format!("{}{}", prefix, "UserName"), &field_value);
        }
    }
}

/// <p>Contains the response to a successful <a>GetUser</a> request. </p>
#[derive(Default, Debug, Clone, PartialEq)]
pub struct GetUserResponse {
    /// <p><p>A structure containing details about the IAM user.</p> <important> <p>Due to a service issue, password last used data does not include password use from May 3, 2018 22:50 PDT to May 23, 2018 14:08 PDT. This affects <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html">last sign-in</a> dates shown in the IAM console and password last used dates in the <a href="http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html">IAM credential report</a>, and returned by this GetUser API. If users signed in during the affected time, the password last used date that is returned is the date the user last signed in before May 3, 2018. For users that signed in after May 23, 2018 14:08 PDT, the returned password last used date is accurate.</p> <p>You can use password last used information to identify unused credentials for deletion. For example, you might delete users who did not sign in to AWS in the last 90 days. In cases like this, we recommend that you adjust your evaluation window to include dates after May 23, 2018. Alternatively, if your users use access keys to access AWS programmatically you can refer to access key last used information because it is accurate for all dates. </p> </important></p>
    pub user: User,
}

struct GetUserResponseDeserializer;
impl GetUserResponseDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<GetUserResponse, XmlParseError> {
        deserialize_elements::<_, GetUserResponse, _>(tag_name, stack, |name, stack, obj| {
            match name {
                "User" => {
                    obj.user = UserDeserializer::deserialize("User", stack)?;
                }
                _ => skip_tree(stack),
            }
            Ok(())
        })
    }
}

struct ListUsersResponseDeserializer;
impl ListUsersResponseDeserializer {
    #[allow(unused_variables)]
    fn deserialize<'a, T: Peek + Next>(
        tag_name: &str,
        stack: &mut T,
    ) -> Result<ListUsersResponse, XmlParseError> {
        deserialize_elements::<_, ListUsersResponse, _>(tag_name, stack, |name, stack, obj| {
            match name {
                "IsTruncated" => {
                    obj.is_truncated =
                        Some(BooleanTypeDeserializer::deserialize("IsTruncated", stack)?);
                }
                "Marker" => {
                    obj.marker = Some(StringTypeDeserializer::deserialize("Marker", stack)?);
                }
                "Users" => {
                    obj.users
                        .extend(UserListTypeDeserializer::deserialize("Users", stack)?);
                }
                _ => skip_tree(stack),
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct IamClient {
    client: Client,
    region: region::Region,
}

impl IamClient {
    /// Creates a client backed by the default tokio event loop.
    ///
    /// The client will use the default credentials provider and tls client.
    pub fn new(region: region::Region) -> IamClient {
        IamClient {
            client: Client::shared(),
            region: region,
        }
    }

    #[allow(unused)]
    pub fn new_with<P, D>(
        request_dispatcher: D,
        credentials_provider: P,
        region: region::Region,
    ) -> IamClient
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
        P::Future: Send,
        D: DispatchSignedRequest + Send + Sync + 'static,
        D::Future: Send,
    {
        IamClient {
            client: Client::new_with(credentials_provider, request_dispatcher),
            region: region,
        }
    }
}

pub trait Iam {
    fn list_ssh_public_keys(
        &self,
        input: ListSSHPublicKeysRequest,
    ) -> RusotoFuture<ListSSHPublicKeysResponse, ListSSHPublicKeysError>;

    fn list_users(
        &self,
        input: ListUsersRequest,
    ) -> RusotoFuture<ListUsersResponse, ListSSHPublicKeysError>;

    fn get_user(
        &self,
        input: GetUserRequest,
    ) -> RusotoFuture<GetUserResponse, ListSSHPublicKeysError>;

    fn get_ssh_public_key(
        &self,
        input: GetSSHPublicKeyRequest,
    ) -> RusotoFuture<GetSSHPublicKeyResponse, ListSSHPublicKeysError>;
}

impl Iam for IamClient {
    fn list_ssh_public_keys(
        &self,
        input: ListSSHPublicKeysRequest,
    ) -> RusotoFuture<ListSSHPublicKeysResponse, ListSSHPublicKeysError> {
        let mut request = SignedRequest::new("POST", "iam", &self.region, "/");
        let mut params = Params::new();

        params.put("Action", "ListSSHPublicKeys");
        params.put("Version", "2010-05-08");
        ListSSHPublicKeysRequestSerializer::serialize(&mut params, "", &input);
        request.set_payload(Some(serde_urlencoded::to_string(&params).unwrap()));
        request.set_content_type("application/x-www-form-urlencoded".to_owned());

        self.client.sign_and_dispatch(request, |response| {
            if !response.status.is_success() {
                return Box::new(
                    response
                        .buffer()
                        .from_err()
                        .and_then(|response| Err(ListSSHPublicKeysError::from_response(response))),
                );
            }

            Box::new(response.buffer().from_err().and_then(move |response| {
                let result;

                if response.body.is_empty() {
                    result = ListSSHPublicKeysResponse::default();
                } else {
                    let reader = EventReader::new_with_config(
                        response.body.as_ref(),
                        ParserConfig::new().trim_whitespace(true),
                    );
                    let mut stack = XmlResponse::new(reader.into_iter().peekable());
                    let _start_document = stack.next();
                    let actual_tag_name = peek_at_name(&mut stack)?;
                    start_element(&actual_tag_name, &mut stack)?;
                    result = ListSSHPublicKeysResponseDeserializer::deserialize(
                        "ListSSHPublicKeysResult",
                        &mut stack,
                    )?;
                    skip_tree(&mut stack);
                    end_element(&actual_tag_name, &mut stack)?;
                }
                // parse non-payload
                Ok(result)
            }))
        })
    }

    /// <p>Lists the IAM users that have the specified path prefix. If no path prefix is specified, the operation returns all users in the AWS account. If there are none, the operation returns an empty list.</p> <p>You can paginate the results using the <code>MaxItems</code> and <code>Marker</code> parameters.</p>
    fn list_users(
        &self,
        input: ListUsersRequest,
    ) -> RusotoFuture<ListUsersResponse, ListSSHPublicKeysError> {
        let mut request = SignedRequest::new("POST", "iam", &self.region, "/");
        let mut params = Params::new();

        params.put("Action", "ListUsers");
        params.put("Version", "2010-05-08");
        ListUsersRequestSerializer::serialize(&mut params, "", &input);
        request.set_payload(Some(serde_urlencoded::to_string(&params).unwrap()));
        request.set_content_type("application/x-www-form-urlencoded".to_owned());

        self.client.sign_and_dispatch(request, |response| {
            if !response.status.is_success() {
                return Box::new(
                    response
                        .buffer()
                        .from_err()
                        .and_then(|response| Err(ListSSHPublicKeysError::from_response(response))),
                );
            }

            Box::new(response.buffer().from_err().and_then(move |response| {
                let result;

                if response.body.is_empty() {
                    result = ListUsersResponse::default();
                } else {
                    let reader = EventReader::new_with_config(
                        response.body.as_ref(),
                        ParserConfig::new().trim_whitespace(true),
                    );
                    let mut stack = XmlResponse::new(reader.into_iter().peekable());
                    let _start_document = stack.next();
                    let actual_tag_name = peek_at_name(&mut stack)?;
                    start_element(&actual_tag_name, &mut stack)?;
                    result =
                        ListUsersResponseDeserializer::deserialize("ListUsersResult", &mut stack)?;
                    skip_tree(&mut stack);
                    end_element(&actual_tag_name, &mut stack)?;
                }
                // parse non-payload
                Ok(result)
            }))
        })
    }

    /// <p>Retrieves information about the specified IAM user, including the user's creation date, path, unique ID, and ARN.</p> <p>If you do not specify a user name, IAM determines the user name implicitly based on the AWS access key ID used to sign the request to this API.</p>
    fn get_user(
        &self,
        input: GetUserRequest,
    ) -> RusotoFuture<GetUserResponse, ListSSHPublicKeysError> {
        let mut request = SignedRequest::new("POST", "iam", &self.region, "/");
        let mut params = Params::new();

        params.put("Action", "GetUser");
        params.put("Version", "2010-05-08");
        GetUserRequestSerializer::serialize(&mut params, "", &input);
        request.set_payload(Some(serde_urlencoded::to_string(&params).unwrap()));
        request.set_content_type("application/x-www-form-urlencoded".to_owned());

        self.client.sign_and_dispatch(request, |response| {
            if !response.status.is_success() {
                return Box::new(
                    response
                        .buffer()
                        .from_err()
                        .and_then(|response| Err(ListSSHPublicKeysError::from_response(response))),
                );
            }

            Box::new(response.buffer().from_err().and_then(move |response| {
                let result;

                if response.body.is_empty() {
                    result = GetUserResponse::default();
                } else {
                    let reader = EventReader::new_with_config(
                        response.body.as_ref(),
                        ParserConfig::new().trim_whitespace(true),
                    );
                    let mut stack = XmlResponse::new(reader.into_iter().peekable());
                    let _start_document = stack.next();
                    let actual_tag_name = peek_at_name(&mut stack)?;
                    start_element(&actual_tag_name, &mut stack)?;
                    result = GetUserResponseDeserializer::deserialize("GetUserResult", &mut stack)?;
                    skip_tree(&mut stack);
                    end_element(&actual_tag_name, &mut stack)?;
                }
                // parse non-payload
                Ok(result)
            }))
        })
    }

    fn get_ssh_public_key(
        &self,
        input: GetSSHPublicKeyRequest,
    ) -> RusotoFuture<GetSSHPublicKeyResponse, ListSSHPublicKeysError> {
        let mut request = SignedRequest::new("POST", "iam", &self.region, "/");
        let mut params = Params::new();

        params.put("Action", "GetSSHPublicKey");
        params.put("Version", "2010-05-08");
        GetSSHPublicKeyRequestSerializer::serialize(&mut params, "", &input);
        request.set_payload(Some(serde_urlencoded::to_string(&params).unwrap()));
        request.set_content_type("application/x-www-form-urlencoded".to_owned());

        self.client.sign_and_dispatch(request, |response| {
            if !response.status.is_success() {
                return Box::new(
                    response
                        .buffer()
                        .from_err()
                        .and_then(|response| Err(ListSSHPublicKeysError::from_response(response))),
                );
            }

            Box::new(response.buffer().from_err().and_then(move |response| {
                let result;

                if response.body.is_empty() {
                    result = GetSSHPublicKeyResponse::default();
                } else {
                    let reader = EventReader::new_with_config(
                        response.body.as_ref(),
                        ParserConfig::new().trim_whitespace(true),
                    );
                    let mut stack = XmlResponse::new(reader.into_iter().peekable());
                    let _start_document = stack.next();
                    let actual_tag_name = peek_at_name(&mut stack)?;
                    start_element(&actual_tag_name, &mut stack)?;
                    result = GetSSHPublicKeyResponseDeserializer::deserialize(
                        "GetSSHPublicKeyResult",
                        &mut stack,
                    )?;
                    skip_tree(&mut stack);
                    end_element(&actual_tag_name, &mut stack)?;
                }
                // parse non-payload
                Ok(result)
            }))
        })
    }
}
