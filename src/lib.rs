#![allow(
    dead_code,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case
)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::ffi::CStr;
use std::slice;

#[macro_use]
extern crate log;

extern crate strum;
#[macro_use]
extern crate strum_macros;

/// Get the TEE quote.
///
/// # Param
/// - **report_data\[IN\]**\
/// user self defined report data.
/// # Return
/// - ***quote***\
/// Return the tee Quote, presented as u8 vector.
/// - ***error***\
/// Failed to get quote.
///
/// # Examples
/// ```
/// use librats_rs::*;
///
/// #[tokio::main]
/// async fn main() {
///     let s = String::from("sample report data");
///     let report_data = s.as_bytes();
///     let quote = get_quote(report_data).await;
///
///     assert!(quote.is_ok())
/// }
/// ```
pub async fn get_quote(report_data: &[u8]) -> Result<Vec<u8>> {
    let mut evidence: attestation_evidence_t = Default::default();

    debug!("report data: {:?}", report_data);

    let err = unsafe { librats_collect_evidence(&mut evidence, report_data.as_ptr()) };
    if err == rats_attester_err_t_RATS_ATTESTER_ERR_NONE {
        let a: &[u8] =
            tokio::task::block_in_place(|| unsafe { serialize_row(&evidence.__bindgen_anon_1) });
        Ok(a.to_vec())
    } else {
        Err(anyhow!("Get quote error: {:?}", err))
    }
}

unsafe fn serialize_row<T: Sized>(src: &T) -> &[u8] {
    slice::from_raw_parts((src as *const T) as *const u8, ::std::mem::size_of::<T>())
}

/// The supported TEE types:
/// - CSV: CSV TEE.
/// - SGX: SGX TEE.
/// - SEVSNP: SEV-SNP TEE.
/// - SEV: SEV-(ES) TEE.
/// - TDX: TDX TEE.
/// - NULL: A dummy TEE that used to test/demo the librats-rs functionalities.
#[derive(Display, Debug, EnumString)]
pub enum TeeType {
    #[strum(serialize = "csv")]
    CSV,
    #[strum(serialize = "sgx_ecdsa")]
    SGX,
    #[strum(serialize = "sev_snp")]
    SEVSNP,
    #[strum(serialize = "sev")]
    SEV,
    #[strum(serialize = "tdx_ecdsa")]
    TDX,
    #[strum(serialize = "nullverifier")]
    NULL,
}

/// Verify the TEE quote.
///
/// # Param
/// - **quote\[IN\]**\
/// TEE Quote, presented as u8 vector.
/// - **report_data\[IN\]**\
/// user self defined report data
/// - **tee\[IN\]**\
/// TEE types
/// # Return
/// - ***tcb_status***\
/// Return the tcb status when verify the quote successfully.
/// - ***error***\
/// Failed to verify quote.
/// # Examples
/// ```
/// use librats_rs::TeeType;
/// use librats_rs::verify_quote;
///
/// #[tokio::main]
/// async fn main() {
///     let s = String::from("sample report data");
///     let report_data = s.as_bytes();
///     let quote = "sample quote".as_bytes();
///
///     let result = verify_quote(quote, report_data, TeeType::NULL).await;
///
///     assert!(result.is_ok());
/// }
/// ```
pub async fn verify_quote(quote: &[u8], report_data: &[u8], tee: TeeType) -> Result<Value> {
    let mut evidence: attestation_evidence_t = Default::default();

    evidence.type_[..tee.to_string().len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(
            tee.to_string().as_bytes().as_ptr() as *const i8,
            tee.to_string().as_bytes().len(),
        )
    });

    evidence.__bindgen_anon_1 = unsafe { std::ptr::read(quote.to_vec().as_ptr() as *const _) };

    debug!("report data: {:?}, tee type: {:?}", report_data, tee);

    let mut claim_length = 0;
    let claim: claim_t = Default::default();
    let mut claims = Box::into_raw(Box::new(claim)) as *mut claim_t;
    let mut claims_map = serde_json::Map::new();

    let err = tokio::task::block_in_place(|| unsafe {
        librats_verify_evidence(
            &mut evidence,
            report_data.as_ptr(),
            &mut claims,
            &mut claim_length,
        )
    });
    if err != rats_verifier_err_t_RATS_VERIFIER_ERR_NONE {
        return Err(anyhow!("verify quote and parse claims error: {:?}", err));
    }

    // Construct parsed claims map
    for i in 0..claim_length {
        let claim_ptr = unsafe { claims.offset(i.try_into().unwrap()) };

        // Convert std::os::raw::c_char to string
        let key = unsafe { CStr::from_ptr((*claim_ptr).name) }
            .to_str()
            .map(|s| s.to_owned())
            .unwrap();

        // Convert *mut u8 to string
        let vaule_ptr = unsafe { (*claim_ptr).value };
        let value_size = unsafe { (*claim_ptr).value_size }.try_into().unwrap();

        let value_byte = unsafe { slice::from_raw_parts(vaule_ptr, value_size) };
        let value = hex::encode(value_byte);

        debug!(
            "key: {:?}, value: {:?}, value_size: {:?}",
            key, value, value_size
        );

        claims_map.insert(key, json!(value));
    }

    // Free the Claims memory
    let err = tokio::task::block_in_place(|| unsafe { free_claims_list(claims, claim_length) });

    if err == rats_err_t_RATS_ERR_NONE {
        Ok(Value::Object(claims_map))
    } else {
        Err(anyhow!("clean up claims memory err: {:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const report_data: &[u8] = "12345678123456781234567812345678".as_bytes();

    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_quote() {
        let evi = get_quote(report_data).await;

        assert!(evi.is_ok() && !evi.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_null_quote() {
        let quote = "test".as_bytes();

        let ret = verify_quote(quote, report_data, TeeType::NULL).await;

        assert!(ret.is_ok() && !ret.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_snp_quote() {
        let snp_evidence = include_bytes!("tests/snp_report.bin").to_vec();

        let snp_ret = verify_quote(&snp_evidence, report_data, TeeType::SEVSNP).await;

        assert!(snp_ret.is_ok() && !snp_ret.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_csv_quote() {
        let csv_evidence = include_bytes!("tests/csv_report.bin").to_vec();

        let csv_ret = verify_quote(&csv_evidence, report_data, TeeType::CSV).await;

        assert!(csv_ret.is_ok() && !csv_ret.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_sev_quote() {
        let sev_evidence = include_bytes!("tests/sev_report.bin").to_vec();

        let sev_ret = verify_quote(&sev_evidence, report_data, TeeType::SEV).await;

        assert!(sev_ret.is_ok() && !sev_ret.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_sgx_ecdsa_quote() {
        let sgx_evidence = include_bytes!("tests/sgx_ecdsa_report.bin").to_vec();

        let sgx_ret = verify_quote(&sgx_evidence, report_data, TeeType::SGX).await;

        assert!(sgx_ret.is_ok() && !sgx_ret.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_tdx_quote() {
        let tdx_evidence = include_bytes!("tests/tdx_report.bin").to_vec();

        let tdx_ret = verify_quote(&tdx_evidence, report_data, TeeType::TDX).await;

        println!("claims: {:#?}", tdx_ret);
        assert!(tdx_ret.is_ok() && !tdx_ret.is_err());
    }
}
