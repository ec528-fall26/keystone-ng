// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared fixtures for unit tests. The RSA key is a throwaway test key.

use chrono::{TimeDelta, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

pub(crate) const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuK74gAzPlU6Dp\nGoCHxqf1rsFA0zraByoNoe1s0syemIQXcX2yd8B03pLOKEXQL9CWpvNSCHrZqfU7\ndSLtMZswfUFjdBYK8++/NKUmmD1HVj+/ZjesATOCTwch5NFnCciSatL1uZeUPuhN\n9CyrX8DlATiAulHRcMTEVTg6XzTD8y6022NHL+dlwnaGwUI+m5y1hfJSMj8YjNqy\nmfldq10zcMBMlDNbqjZeCXo32OYHZsNk7SIgvvUsNA2OWd50DJ7wTXkn8+JxvkoY\n/WAY8NNIZHIk4hwkaKWXpi+CJM6T72rck3aD7U4ZWD3J2HdfW/PXxUGQzbwfe7D3\nfbljy4w3AgMBAAECggEASbkZSpqgcl8yOsktg4tal/tnMMXYYOZsbgXPJmOaGj2L\nmBLBdnQLAk0eDeZtGqDKpaI4V05gldbDh23fIVCAlIdIUM0X8X3syt4BU/NX6OTA\nqgcd5JBDmdJSvg2Jd5hkDlnqPvnWh/kSwsBq0gV/dE/Od2qmbEVT/Jjn6olXH+OS\nZB6pvGCK7kBzpT9stBM4SDdk9cOxckxUH01zHwDCwRTv1lJHgUlo7w3SAKpFE9Jc\n2rk3T4O0hf/q/0VxnyNVhEY4NYjGDg2X0LtK8Aq4ESzejmw/bK7HF1DDyRmMLg4b\nZraxFwUU3iCTGyFcfwlSHFUp+swGsySnrycsGq3kKQKBgQDXNA27sSJ3mEmDwk50\nu/7jLzcB57Xe+Eue8ViveYgrn0lc9N4CghQUIU1Z8/TlWboziqr4Q0Z3FXw/H1BO\nhk/Yg6rHw9JazS1qbtVV3Q8kFCwfri+8kV3GQv2I6hwb8rBrGssw4+k/zl+Fpfst\n23V11nPRvrze6R+4vBF2aDegDwKBgQDPMFvoKn9p5frBdoAQfWTuY9kSk/Yed1Oi\ns3CBoYvqPXqm4yywgpwWsDGGP4qjKWd41OHcRCCIJoDxlAsxKDHsY5EC8dQPtS4l\nINsCU6N77D5qU1g6Ln4kQITohdBm7IKY7T4WhE5Yac8Jgm2O1c7+0XF+SoFmUR93\nIPiXOIWpWQKBgQDNSV2UXxwnA8GVC+T1nGQ/6clKavPmN+tDOq1D7uYD3tYH85pY\nwCdRMJduKLbDlj12b2A6pUpxzLASMtfToHJIcwmVuGpQrgsVzZZ6av7Hhuq0aeAl\nvHG88CiU0+ZujqrV8OBFyhO2BzK99iDOlNvOxf0D5zSaW74j5luuHSp65wKBgQDF\n2nBp7OtvvWcQiJETLivMWx1YWGOYBGuh26l8oUBzl/IgnKB4jsFwCSHCCbvixA9D\nnEdziLtoSRypla56auAB1bMNFNJljadbXVzHhAeCt7+C2cRPC0b6Z4KEagTxxLmS\nQDwiVIZcd+52Lk9hL1xUir3O1Gdtxdo+cQXzos5BQQKBgHa1rNI2Fmtwp9Xgi1c6\nxc1BmTNKQnQmkxqYSK2XLm1Ak1EVDN+gXdZvAEJ0ClHqBiNz4Y01mstjIdrl8F/l\nnBmzTYKLaMSNkZEwGUDE31Uolp9AN78qGmXZlrHhdAq/U+x0tOFpFNa+OoOXgOEM\nY49OPPwO0R/zQrT3fLIjhZ4Z\n-----END PRIVATE KEY-----\n";
pub(crate) const TEST_JWK_N: &str = "riu-IAMz5VOg6RqAh8an9a7BQNM62gcqDaHtbNLMnpiEF3F9snfAdN6SzihF0C_QlqbzUgh62an1O3Ui7TGbMH1BY3QWCvPvvzSlJpg9R1Y_v2Y3rAEzgk8HIeTRZwnIkmrS9bmXlD7oTfQsq1_A5QE4gLpR0XDExFU4Ol80w_MutNtjRy_nZcJ2hsFCPpuctYXyUjI_GIzaspn5XatdM3DATJQzW6o2Xgl6N9jmB2bDZO0iIL71LDQNjlnedAye8E15J_Picb5KGP1gGPDTSGRyJOIcJGill6YvgiTOk-9q3JN2g-1OGVg9ydh3X1vz18VBkM28H3uw9325Y8uMNw";
pub(crate) const TEST_JWK_E: &str = "AQAB";
pub(crate) const TEST_KID: &str = "test-kid";

pub(crate) fn rsa_jwk(kid: &str) -> jsonwebtoken::jwk::Jwk {
    serde_json::from_value(json!({
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": TEST_JWK_N, "e": TEST_JWK_E,
    }))
    .expect("hard-coded test JWK must deserialize")
}

pub(crate) fn make_jwt(claims: &serde_json::Value, kid: Option<&str>) -> String {
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
        .expect("hard-coded test RSA private key must parse");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    encode(&header, claims, &key).expect("test JWT must encode")
}

pub(crate) fn valid_claims(iss: &str, aud: &str, nonce: Option<&str>) -> serde_json::Value {
    let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
    let mut c = json!({
        "sub": "user123", "iss": iss, "aud": aud,
        "exp": exp, "iat": Utc::now().timestamp(),
    });
    if let Some(n) = nonce {
        c["nonce"] = json!(n);
    }
    c
}
