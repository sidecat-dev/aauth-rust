//! gRPC definitions: a complete binary `google.protobuf.FileDescriptorSet`.
//!
//! Hosted `.proto` text and live server reflection are refused. Nothing here
//! dials a server or compiles schemas. Derived operations are
//! `package.Service/Method`. Input and output type strings must be non-empty.
//! Those types do not need message descriptors in the set, and a dependency
//! that is not itself a file in the set is unresolved.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::OnceLock;

use crate::definition::{
    AuthoritativeSnapshot, DefinedOperation, DefinitionCodec, DefinitionError, DefinitionErrorKind,
    DefinitionMaterial, DefinitionParser, DefinitionRegistration, SourceEncoding,
};
use crate::definition_support::{
    cached_parser, incomplete, invalid, parse_standard, single_member_operation, unavailable,
    unsupported,
};
use crate::error::Error;
use crate::standard::GrpcCodec;

const DESCRIPTOR_ENCODING: &str =
    "application/x-protobuf;message=google.protobuf.FileDescriptorSet";
const HOSTED_PROTO_REFUSAL: &str = "hosted .proto text must be compiled and dependency-resolved into a complete FileDescriptorSet before parsing";
const REFLECTION_REFUSAL: &str =
    "live server reflection must be acquired into a complete FileDescriptorSet before parsing";
const ABSENT_SOURCE: &str = "gRPC definition source is absent";

const SET_FILE: u32 = 1;
const FILE_NAME: u32 = 1;
const FILE_PACKAGE: u32 = 2;
const FILE_DEPENDENCY: u32 = 3;
const FILE_MESSAGE: u32 = 4;
const FILE_SERVICE: u32 = 6;
const FILE_SYNTAX: u32 = 12;
const SERVICE_NAME: u32 = 1;
const SERVICE_METHOD: u32 = 2;
const METHOD_NAME: u32 = 1;
const METHOD_INPUT: u32 = 2;
const METHOD_OUTPUT: u32 = 3;
const WIRE_VARINT: u32 = 0;
const WIRE_FIXED64: u32 = 1;
const WIRE_BYTES: u32 = 2;
const WIRE_FIXED32: u32 = 5;
const MAX_FIELD: u32 = (1 << 29) - 1;

fn method_identity(package: &str, service: &str, method: &str) -> String {
    format!("{package}.{service}/{method}")
}

/// Which already-acquired gRPC input the caller holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrpcSourceKind {
    /// Complete binary descriptor set.
    FileDescriptorSet,
    /// `.proto` text that this parser does not compile.
    HostedProtoText,
    /// Live reflection that this parser does not dial.
    ServerReflection,
}

/// Owned binary `FileDescriptorSet`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorSetSource {
    exact: Vec<u8>,
}

impl DescriptorSetSource {
    /// Copy `exact`.
    pub fn new(exact: &[u8]) -> Self {
        Self {
            exact: exact.to_vec(),
        }
    }
    /// Exact descriptor bytes.
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact
    }
    /// [`GrpcSourceKind::FileDescriptorSet`].
    pub fn kind(&self) -> GrpcSourceKind {
        GrpcSourceKind::FileDescriptorSet
    }
}

/// Hosted `.proto` text. Parsing refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedProtoTextSource {
    exact: Vec<u8>,
}

impl HostedProtoTextSource {
    /// Copy `exact`. Parsing does not compile it.
    pub fn new(exact: &[u8]) -> Self {
        Self {
            exact: exact.to_vec(),
        }
    }
    /// [`GrpcSourceKind::HostedProtoText`].
    pub fn kind(&self) -> GrpcSourceKind {
        GrpcSourceKind::HostedProtoText
    }
}

/// A live reflection target. Parsing never contacts it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerReflectionSource;

impl ServerReflectionSource {
    /// Construct an explicit live-reflection source.
    pub fn new() -> Self {
        Self
    }
    /// [`GrpcSourceKind::ServerReflection`].
    pub fn kind(self) -> GrpcSourceKind {
        GrpcSourceKind::ServerReflection
    }
}

/// One already-acquired gRPC definition input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrpcDefinitionSource {
    /// Complete binary descriptor set.
    DescriptorSet(DescriptorSetSource),
    /// Hosted `.proto` text.
    HostedProtoText(HostedProtoTextSource),
    /// Live server reflection.
    ServerReflection(ServerReflectionSource),
    /// Absent source.
    Absent,
}

impl GrpcDefinitionSource {
    /// Descriptor bytes.
    pub fn descriptor_set(exact: &[u8]) -> Self {
        Self::DescriptorSet(DescriptorSetSource::new(exact))
    }
    /// Hosted `.proto` text.
    pub fn hosted_proto_text(exact: &[u8]) -> Self {
        Self::HostedProtoText(HostedProtoTextSource::new(exact))
    }
    /// Live reflection. Parsing does not dial it.
    pub fn server_reflection() -> Self {
        Self::ServerReflection(ServerReflectionSource::new())
    }
    /// Absent source.
    pub fn absent() -> Self {
        Self::Absent
    }
}

struct GrpcDefinitionCodec;

impl DefinitionCodec<GrpcDefinitionSource> for GrpcDefinitionCodec {
    fn vocabulary(&self) -> Result<crate::Vocabulary, Error> {
        GrpcCodec::vocabulary()
    }
    fn parse_definition(
        &self,
        source: &GrpcDefinitionSource,
    ) -> Result<DefinitionMaterial, DefinitionError> {
        parse_grpc_source(source)
    }
}

impl GrpcCodec {
    /// Process-wide gRPC definition parser.
    ///
    /// # Errors
    /// Returns [`Error`] when the gRPC vocabulary is unavailable.
    pub fn definition_parser() -> Result<DefinitionParser<GrpcDefinitionSource>, Error> {
        static PARSER: OnceLock<Option<DefinitionParser<GrpcDefinitionSource>>> = OnceLock::new();
        cached_parser(
            &PARSER,
            || DefinitionParser::new(GrpcDefinitionCodec),
            Self::URI,
        )
    }

    /// Derive methods from one descriptor set, or refuse an unsupported source.
    ///
    /// # Errors
    /// Returns a typed [`DefinitionError`]. This performs no I/O.
    pub fn parse_definition(
        endpoint: &str,
        source: &GrpcDefinitionSource,
    ) -> Result<AuthoritativeSnapshot, DefinitionError> {
        parse_standard(Self::definition_parser(), Self::URI, endpoint, source)
    }

    /// Registration of [`Self::definition_parser`].
    ///
    /// # Errors
    /// Returns [`Error`] when the gRPC vocabulary is unavailable.
    pub fn definition_registration() -> Result<DefinitionRegistration, Error> {
        Self::definition_parser().map(|parser| parser.registration())
    }
}

fn parse_grpc_source(source: &GrpcDefinitionSource) -> Result<DefinitionMaterial, DefinitionError> {
    match source {
        GrpcDefinitionSource::HostedProtoText(_) => Err(unsupported(HOSTED_PROTO_REFUSAL)),
        GrpcDefinitionSource::ServerReflection(_) => Err(unsupported(REFLECTION_REFUSAL)),
        GrpcDefinitionSource::Absent => Err(incomplete(ABSENT_SOURCE)),
        GrpcDefinitionSource::DescriptorSet(descriptor) => {
            definition_from_descriptor(&descriptor.exact)
        }
    }
}

fn definition_from_descriptor(exact: &[u8]) -> Result<DefinitionMaterial, DefinitionError> {
    let files = decode_file_descriptor_set(exact).map_err(|err| {
        invalid("invalid binary FileDescriptorSet").with_cause(Error::new(err.to_string()))
    })?;
    validate_files(&files)?;
    let mut methods = Vec::new();
    for file in &files {
        for service in &file.services {
            for method in &service.methods {
                methods.push(format!("{}.{}/{}", file.package, service.name, method.name));
            }
        }
    }
    if methods.is_empty() {
        return Err(incomplete("FileDescriptorSet defines no service methods"));
    }
    methods.sort();
    let mut operations = Vec::with_capacity(methods.len());
    for (index, method) in methods.iter().enumerate() {
        if index > 0 && methods[index - 1] == *method {
            return Err(crate::definition::DefinitionError::new(
                DefinitionErrorKind::IdentityAmbiguous,
                format!("gRPC method {method:?} occurs more than once"),
            ));
        }
        check_method(method).map_err(|err| {
            unavailable(format!("invalid gRPC method identity {method:?}")).with_cause(err)
        })?;
        operations.push(
            DefinedOperation::new(&single_member_operation("method", method), None)
                .map_err(|err| invalid("gRPC method encoding failed").with_cause(err))?,
        );
    }
    let encoding = SourceEncoding::new(DESCRIPTOR_ENCODING)
        .map_err(|err| invalid("invalid descriptor encoding").with_cause(err))?;
    DefinitionMaterial::new(encoding, exact.to_vec(), operations)
        .map_err(|err| invalid("invalid definition material").with_cause(err))
}

fn check_method(method: &str) -> Result<(), Error> {
    let valid = method.split_once('/').is_some_and(|(service, name)| {
        service
            .rsplit_once('.')
            .is_some_and(|(package, service_name)| {
                !package.is_empty() && package.split('.').all(is_ident) && is_ident(service_name)
            })
            && is_ident(name)
    });
    if valid {
        Ok(())
    } else {
        Err(Error::new(format!(
            "method \"{method}\" is not package.ServiceName/MethodName"
        )))
    }
}

fn is_ident(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|first| first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

#[derive(Default)]
struct FileProto {
    name: String,
    package: String,
    dependencies: Vec<String>,
    services: Vec<ServiceProto>,
}

#[derive(Default)]
struct ServiceProto {
    name: String,
    methods: Vec<MethodProto>,
}

#[derive(Default)]
struct MethodProto {
    name: String,
    input_type: String,
    output_type: String,
}

struct ProtoFailure {
    message: &'static str,
}

impl ProtoFailure {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for ProtoFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

struct Reader<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
    }

    fn done(&self) -> bool {
        self.index >= self.data.len()
    }

    fn read_byte(&mut self) -> Result<u8, ProtoFailure> {
        let byte = self
            .data
            .get(self.index)
            .copied()
            .ok_or(ProtoFailure::new("truncated FileDescriptorSet"))?;
        self.index += 1;
        Ok(byte)
    }

    fn read_varint(&mut self) -> Result<u64, ProtoFailure> {
        let mut value = 0u64;
        for byte_index in 0u32..10 {
            let byte = self.read_byte()?;
            if byte_index == 9 && byte > 1 {
                return Err(ProtoFailure::new("varint overflows"));
            }
            value |= u64::from(byte & 0x7f) << (byte_index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ProtoFailure::new("varint is too long"))
    }

    fn read_key(&mut self) -> Result<(u32, u32), ProtoFailure> {
        let tag = self.read_varint()?;
        let tag = u32::try_from(tag).map_err(|_| ProtoFailure::new("field number is too large"))?;
        let wire = tag & 7;
        let field = tag >> 3;
        if field == 0 || field > MAX_FIELD {
            return Err(ProtoFailure::new("field number is invalid"));
        }
        Ok((field, wire))
    }

    fn read_len(&mut self) -> Result<usize, ProtoFailure> {
        let len = self.read_varint()?;
        let len = usize::try_from(len).map_err(|_| ProtoFailure::new("length does not fit"))?;
        let end = self
            .index
            .checked_add(len)
            .ok_or(ProtoFailure::new("length overflows"))?;
        if end > self.data.len() {
            return Err(ProtoFailure::new("truncated length-delimited field"));
        }
        Ok(len)
    }

    fn skip_bytes(&mut self, len: usize) -> Result<(), ProtoFailure> {
        let end = self
            .index
            .checked_add(len)
            .ok_or(ProtoFailure::new("length overflows"))?;
        if end > self.data.len() {
            return Err(ProtoFailure::new("truncated fixed field"));
        }
        self.index = end;
        Ok(())
    }

    fn read_delimited(&mut self) -> Result<Vec<u8>, ProtoFailure> {
        let len = self.read_len()?;
        let start = self.index;
        self.index += len;
        Ok(self.data[start..self.index].to_vec())
    }

    fn read_string(&mut self) -> Result<String, ProtoFailure> {
        let bytes = self.read_delimited()?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ProtoFailure::new("protobuf string is not UTF-8"))?;
        Ok(text.to_owned())
    }

    fn skip(&mut self, wire: u32) -> Result<(), ProtoFailure> {
        match wire {
            WIRE_VARINT => {
                let _value = self.read_varint()?;
                Ok(())
            }
            WIRE_FIXED64 => self.skip_bytes(8),
            WIRE_BYTES => {
                let len = self.read_len()?;
                self.skip_bytes(len)
            }
            WIRE_FIXED32 => self.skip_bytes(4),
            _ => Err(ProtoFailure::new("unsupported protobuf wire type")),
        }
    }
}

fn validate_files(files: &[FileProto]) -> Result<(), DefinitionError> {
    if files.is_empty() {
        return Err(DefinitionError::new(
            DefinitionErrorKind::IncompleteSource,
            "FileDescriptorSet contains no files",
        ));
    }
    let mut names = BTreeSet::new();
    for (index, file) in files.iter().enumerate() {
        if file.name.is_empty() {
            return Err(DefinitionError::new(
                DefinitionErrorKind::IncompleteSource,
                format!("FileDescriptorSet file {index} has no name"),
            ));
        }
        if !names.insert(file.name.clone()) {
            return Err(DefinitionError::new(
                DefinitionErrorKind::InvalidSource,
                format!("FileDescriptorSet repeats file {:?}", file.name),
            ));
        }
    }
    let mut methods = BTreeSet::new();
    for (file_index, file) in files.iter().enumerate() {
        for dependency in &file.dependencies {
            if !names.contains(dependency) {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::UnresolvedDependency,
                    format!(
                        "file {:?} imports missing descriptor {dependency:?}",
                        file.name
                    ),
                ));
            }
        }
        if !file.services.is_empty() && file.package.is_empty() {
            return Err(DefinitionError::new(
                DefinitionErrorKind::IncompleteSource,
                format!("file {:?} defines services without a package", file.name),
            ));
        }
        for (service_index, service) in file.services.iter().enumerate() {
            if service.name.is_empty() {
                return Err(DefinitionError::new(
                    DefinitionErrorKind::IncompleteSource,
                    format!("file {file_index} service {service_index} has no identity"),
                ));
            }
            for (method_index, method) in service.methods.iter().enumerate() {
                if method.name.is_empty()
                    || method.input_type.is_empty()
                    || method.output_type.is_empty()
                {
                    return Err(DefinitionError::new(
                        DefinitionErrorKind::IncompleteSource,
                        format!(
                            "file {:?} service {:?} method {method_index} is incomplete",
                            file.name, service.name
                        ),
                    ));
                }
                let identity = method_identity(&file.package, &service.name, &method.name);
                if let Err(err) = check_method(&identity) {
                    return Err(
                        unavailable(format!("invalid gRPC method identity {identity:?}"))
                            .with_cause(err),
                    );
                }
                if !methods.insert(identity.clone()) {
                    return Err(DefinitionError::new(
                        DefinitionErrorKind::IdentityAmbiguous,
                        format!("gRPC method {identity:?} occurs more than once"),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn decode_file_descriptor_set(data: &[u8]) -> Result<Vec<FileProto>, ProtoFailure> {
    let mut reader = Reader::new(data);
    let mut files = Vec::new();
    while !reader.done() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (SET_FILE, WIRE_BYTES) => {
                let bytes = reader.read_delimited()?;
                files.push(parse_file(&bytes)?);
            }
            (SET_FILE, _) => {
                return Err(ProtoFailure::new(
                    "FileDescriptorSet.file has the wrong wire type",
                ));
            }
            (_, other) => reader.skip(other)?,
        }
    }
    Ok(files)
}

fn parse_file(bytes: &[u8]) -> Result<FileProto, ProtoFailure> {
    let mut reader = Reader::new(bytes);
    let mut file = FileProto::default();
    while !reader.done() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (FILE_NAME, WIRE_BYTES) => file.name = reader.read_string()?,
            (FILE_NAME, _) => {
                return Err(ProtoFailure::new("file name has the wrong wire type"));
            }
            (FILE_PACKAGE, WIRE_BYTES) => file.package = reader.read_string()?,
            (FILE_PACKAGE, _) => {
                return Err(ProtoFailure::new("file package has the wrong wire type"));
            }
            (FILE_DEPENDENCY, WIRE_BYTES) => file.dependencies.push(reader.read_string()?),
            (FILE_DEPENDENCY, _) => {
                return Err(ProtoFailure::new("file dependency has the wrong wire type"));
            }
            (FILE_MESSAGE, WIRE_BYTES) => {
                let _message = reader.read_delimited()?;
            }
            (FILE_MESSAGE, _) => {
                return Err(ProtoFailure::new("message type has the wrong wire type"));
            }
            (FILE_SERVICE, WIRE_BYTES) => {
                let bytes = reader.read_delimited()?;
                file.services.push(parse_service(&bytes)?);
            }
            (FILE_SERVICE, _) => {
                return Err(ProtoFailure::new("service has the wrong wire type"));
            }
            (FILE_SYNTAX, WIRE_BYTES) => {
                let _syntax = reader.read_string()?;
            }
            (FILE_SYNTAX, _) => return Err(ProtoFailure::new("syntax has the wrong wire type")),
            (_, other) => reader.skip(other)?,
        }
    }
    Ok(file)
}

fn parse_service(bytes: &[u8]) -> Result<ServiceProto, ProtoFailure> {
    let mut reader = Reader::new(bytes);
    let mut service = ServiceProto::default();
    while !reader.done() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (SERVICE_NAME, WIRE_BYTES) => service.name = reader.read_string()?,
            (SERVICE_NAME, _) => {
                return Err(ProtoFailure::new("service name has the wrong wire type"));
            }
            (SERVICE_METHOD, WIRE_BYTES) => {
                let bytes = reader.read_delimited()?;
                service.methods.push(parse_method(&bytes)?);
            }
            (SERVICE_METHOD, _) => {
                return Err(ProtoFailure::new("service method has the wrong wire type"));
            }
            (_, other) => reader.skip(other)?,
        }
    }
    Ok(service)
}

fn parse_method(bytes: &[u8]) -> Result<MethodProto, ProtoFailure> {
    let mut reader = Reader::new(bytes);
    let mut method = MethodProto::default();
    while !reader.done() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (METHOD_NAME, WIRE_BYTES) => method.name = reader.read_string()?,
            (METHOD_NAME, _) => {
                return Err(ProtoFailure::new("method name has the wrong wire type"));
            }
            (METHOD_INPUT, WIRE_BYTES) => method.input_type = reader.read_string()?,
            (METHOD_INPUT, _) => {
                return Err(ProtoFailure::new(
                    "method input type has the wrong wire type",
                ));
            }
            (METHOD_OUTPUT, WIRE_BYTES) => method.output_type = reader.read_string()?,
            (METHOD_OUTPUT, _) => {
                return Err(ProtoFailure::new(
                    "method output type has the wrong wire type",
                ));
            }
            (_, other) => reader.skip(other)?,
        }
    }
    Ok(method)
}

#[cfg(test)]
mod tests {
    use super::{GrpcCodec, GrpcDefinitionSource};
    use crate::definition::DefinitionErrorKind;

    const ENDPOINT: &str = "https://resource.example/grpc";

    fn delimited(field: u32, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 128, "fixture length stays in one byte");
        let mut out = Vec::new();
        out.push(u8::try_from((field << 3) | super::WIRE_BYTES).expect("tag"));
        out.push(u8::try_from(value.len()).expect("length"));
        out.extend_from_slice(value);
        out
    }

    fn text_field(field: u32, value: &str) -> Vec<u8> {
        delimited(field, value.as_bytes())
    }

    fn join(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flatten().copied().collect()
    }

    /// One method and no message descriptors. That is the descriptor profile.
    fn calendar_read_descriptor() -> Vec<u8> {
        let method = join(&[
            text_field(super::METHOD_NAME, "Read"),
            text_field(super::METHOD_INPUT, ".example.calendar.Req"),
            text_field(super::METHOD_OUTPUT, ".example.calendar.Res"),
        ]);
        let service = join(&[
            text_field(super::SERVICE_NAME, "Calendar"),
            delimited(super::SERVICE_METHOD, &method),
        ]);
        let file = join(&[
            text_field(super::FILE_NAME, "calendar.proto"),
            text_field(super::FILE_PACKAGE, "example.calendar"),
            delimited(super::FILE_SERVICE, &service),
        ]);
        delimited(super::SET_FILE, &file)
    }

    fn refusal(
        result: Result<crate::AuthoritativeSnapshot, crate::DefinitionError>,
    ) -> crate::DefinitionError {
        match result {
            Err(err) => err,
            Ok(_) => panic!("expected a definition refusal"),
        }
    }

    #[test]
    fn descriptor_profile_derives_methods_without_message_descriptors() {
        let snapshot = GrpcCodec::parse_definition(
            ENDPOINT,
            &GrpcDefinitionSource::descriptor_set(&calendar_read_descriptor()),
        )
        .expect("descriptor");
        let names: Vec<String> = snapshot
            .operations()
            .operations()
            .expect("operations")
            .iter()
            .map(|operation| String::from_utf8(operation.json().expect("json")).expect("utf8"))
            .collect();
        assert_eq!(
            names,
            vec![r#"{"method":"example.calendar.Calendar/Read"}"#.to_owned()]
        );
    }

    #[test]
    fn hosted_proto_and_reflection_are_outside_the_descriptor_profile() {
        let text = GrpcDefinitionSource::hosted_proto_text(b"syntax = \"proto3\";");
        assert_eq!(
            refusal(GrpcCodec::parse_definition(ENDPOINT, &text)).kind(),
            DefinitionErrorKind::SourceKindUnsupported
        );
        assert_eq!(
            refusal(GrpcCodec::parse_definition(
                ENDPOINT,
                &GrpcDefinitionSource::server_reflection()
            ))
            .kind(),
            DefinitionErrorKind::SourceKindUnsupported
        );
        assert_eq!(
            refusal(GrpcCodec::parse_definition(
                ENDPOINT,
                &GrpcDefinitionSource::descriptor_set(&[0xff])
            ))
            .kind(),
            DefinitionErrorKind::InvalidSource
        );
        let missing = join(&[
            text_field(super::FILE_NAME, "calendar.proto"),
            text_field(super::FILE_PACKAGE, "example.calendar"),
            text_field(super::FILE_DEPENDENCY, "missing.proto"),
        ]);
        assert_eq!(
            refusal(GrpcCodec::parse_definition(
                ENDPOINT,
                &GrpcDefinitionSource::descriptor_set(&delimited(super::SET_FILE, &missing))
            ))
            .kind(),
            DefinitionErrorKind::UnresolvedDependency
        );
    }
}
