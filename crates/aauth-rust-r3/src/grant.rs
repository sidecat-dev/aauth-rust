use serde::{Deserialize, Serialize, Serializer};

use crate::document::Document;
use crate::error::Error;
use crate::jsonvalue::refuse_deserialize;
use crate::vocabulary::{GrantedOperations, Registry, compatible_grant_and_set, compatible_grants};

/// A direct grant proven not to exceed one R3 document.
///
/// [`Default`] is unproven and cannot be serialized.
#[derive(Clone, Default)]
pub struct Grant {
    granted: GrantedOperations,
    proven: bool,
}

impl Grant {
    /// Prove `granted` is compatible with `document` and contained by its operation set.
    ///
    /// An empty grant is a subset.
    ///
    /// # Errors
    /// Returns [`Error`] when the operands disagree or the grant is broader than the document.
    pub fn new(granted: &GrantedOperations, document: &Document) -> Result<Self, Error> {
        let operation_set = document.operation_set();
        compatible_grant_and_set(granted, &operation_set)?;
        if !granted.is_subset_of(&operation_set)? {
            return Err(Error::new("r3: grant exceeds document operation set"));
        }
        Ok(Self {
            granted: granted.clone(),
            proven: true,
        })
    }

    /// Copy of the proven grant set.
    pub fn granted_operations(&self) -> GrantedOperations {
        self.granted.clone()
    }
}

impl Serialize for Grant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !self.proven {
            return Err(serde::ser::Error::custom(
                "r3: cannot marshal an unproven Grant; use Grant::new or Registry::parse_grant",
            ));
        }
        self.granted.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Grant {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        refuse_deserialize(
            deserializer,
            "r3: Grant requires registry and document context; use Registry::parse_grant",
        )
    }
}

impl Registry {
    /// Parse a grant envelope and prove it against `document`.
    ///
    /// # Errors
    /// Returns [`Error`] when the JSON is not a grant or it exceeds `document`.
    pub fn parse_grant(&self, source: &[u8], document: &Document) -> Result<Grant, Error> {
        let granted = self.parse_granted_operations(source)?;
        Grant::new(&granted, document)
    }
}

/// Direct and per-call sets proven against one document and against each other.
#[derive(Clone)]
pub struct Authorization {
    granted: GrantedOperations,
    per_call: GrantedOperations,
    proven: bool,
}

impl Authorization {
    /// Prove both sets are subsets of `document` and share no operation.
    ///
    /// # Errors
    /// Returns [`Error`] when an operand is incompatible, either set exceeds the
    /// document, or the sets overlap.
    pub fn new(
        granted: &GrantedOperations,
        per_call: &GrantedOperations,
        document: &Document,
    ) -> Result<Self, Error> {
        let operation_set = document.operation_set();
        compatible_grant_and_set(granted, &operation_set)
            .map_err(|err| Error::wrap("r3: direct authorization", err))?;
        compatible_grant_and_set(per_call, &operation_set)
            .map_err(|err| Error::wrap("r3: per-call authorization", err))?;
        if !granted.is_subset_of(&operation_set)? {
            return Err(Error::new(
                "r3: direct authorization exceeds document operation set",
            ));
        }
        if !per_call.is_subset_of(&operation_set)? {
            return Err(Error::new(
                "r3: per-call authorization exceeds document operation set",
            ));
        }
        compatible_grants(granted, per_call)?;
        if !granted.is_disjoint(per_call)? {
            return Err(Error::new("r3: direct and per-call authorization overlap"));
        }
        Ok(Self {
            granted: granted.clone(),
            per_call: per_call.clone(),
            proven: true,
        })
    }

    /// Copy of the direct grant.
    pub fn granted_operations(&self) -> GrantedOperations {
        self.granted.clone()
    }

    /// Copy of the per-call set.
    pub fn per_call_operations(&self) -> GrantedOperations {
        self.per_call.clone()
    }

    /// Whether [`Authorization::new`] produced this value.
    pub fn is_proven(&self) -> bool {
        self.proven
    }
}
