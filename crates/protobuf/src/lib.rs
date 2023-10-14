pub mod tss {
    include!(concat!(env!("OUT_DIR"), "/tss.rs"));
    pub mod ecdsa {
        pub mod keygen {
            include!(concat!(env!("OUT_DIR"), "/tss.ecdsa.keygen.rs"));
        }
        pub mod resharing {
            include!(concat!(env!("OUT_DIR"), "/tss.ecdsa.resharing.rs"));
        }
        pub mod signing {
            include!(concat!(env!("OUT_DIR"), "/tss.ecdsa.signing.rs"));
        }
    }
    pub mod eddsa {
        pub mod keygen {
            include!(concat!(env!("OUT_DIR"), "/tss.eddsa.keygen.rs"));
        }
        pub mod resharing {
            include!(concat!(env!("OUT_DIR"), "/tss.eddsa.resharing.rs"));
        }
        pub mod signing {
            include!(concat!(env!("OUT_DIR"), "/tss.eddsa.signing.rs"));
        }
    }
}
