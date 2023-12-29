use crate::hash::hash_sha512_256i_tagged;
use crate::utils::{ecdsa, NTildei};
use crate::Result;
use crate::{paillier, CryptoError};
use bytes::Bytes;
use common::mod_int::ModInt;
use common::random::{get_random_positive_int, get_random_positive_relatively_prime_int};
use elliptic_curve::ops::MulByGenerator;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, FieldBytesSize};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use once_cell::sync::Lazy;
use slog::*;
use slog_async;
use slog_term;

static LOGGER: Lazy<Logger> = Lazy::new(|| {
    let drain = slog_term::FullFormat::new(slog_term::TermDecorator::new().build())
        .build()
        .fuse();
    // let drain = Mutex::new(slog_json::Json::default(io::stdout())).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    Logger::root(
        drain,
        o!(
            "version" => env!("CARGO_PKG_VERSION")
        ),
    )
});

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProofBob {
    z: BigUint,
    z_prm: BigUint,
    t: BigUint,
    v: BigUint,
    w: BigUint,
    s: BigUint,
    s1: BigUint,
    s2: BigUint,
    t1: BigUint,
    t2: BigUint,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProofBobWC<C>
where
    C: CurveArithmetic,
{
    bob: ProofBob,
    u: C::AffinePoint,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ParamOfProofBob {
    pub session: Bytes,
    pub pk: paillier::PublicKey,
    pub n_tilde: NTildei,
    pub c1: BigUint,
    pub c2: BigUint,
}

impl ProofBob {
    const NUM_PARTS: usize = 10;
    const NUM_PARTS_WITH_POINT: usize = ProofBob::NUM_PARTS + 2;

    pub fn new<C>(param: &ParamOfProofBob, xy: &(BigUint, BigUint), r: &BigUint) -> Result<Self>
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let wc = ProofBobWC::<C>::create(param, xy, r, None)?;
        Ok(wc.bob)
    }

    pub fn verify<C>(&self, param: &ParamOfProofBob) -> bool
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        self.verify_with_wc::<C>(param, None)
    }

    fn verify_with_wc<C>(
        &self,
        param: &ParamOfProofBob,
        xu: Option<(&C::AffinePoint, &C::AffinePoint)>,
    ) -> bool
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let h1 = &param.n_tilde.v1;
        let h2 = &param.n_tilde.v2;
        let c1 = &param.c1;
        let c2 = &param.c2;
        let n_tilde = &param.n_tilde.n;
        let pk = &param.pk;

        let n2 = &pk.n().pow(2);
        let q = &ecdsa::curve_n::<C>();
        let q3 = &q.pow(3);
        let q7 = &(q3.pow(2) * q);

        if [
            (&self.z, n_tilde),
            (&self.z_prm, n_tilde),
            (&self.t, n_tilde),
            (&self.v, n2),
            (&self.w, n_tilde),
            (&self.s, pk.n()),
        ]
        .into_iter()
        .any(|(a, b)| a >= b)
        {
            warn!(LOGGER, "ProofBob: check a < b");
            return false;
        }

        if [
            (&self.z, n_tilde),
            (&self.z_prm, n_tilde),
            (&self.t, n_tilde),
            (&self.v, n2),
            (&self.w, n_tilde),
            (&self.s, pk.n()),
            (&self.v, pk.n()),
        ]
        .into_iter()
        .any(|(a, b)| !a.gcd(b).is_one())
        {
            warn!(LOGGER, "ProofBob: check gcd(a, b) == 1");
            return false;
        }

        if [&self.s1, &self.s2, &self.t1, &self.t2]
            .into_iter()
            .any(|a| a < q)
        {
            warn!(LOGGER, "ProofBob: check s1, s2, t1, t2 < q";
                "s1" => %(&self.s1),
                "s2" => %(&self.s2),
                "t1" => %(&self.t1),
                "t2" => %(&self.t2),
            );
            return false;
        }

        // 3.
        if &self.s1 > q3 {
            warn!(LOGGER, "ProofBob: check s1 < q3";
                "s1" => %(&self.s1),
                "q3" => %q3,
            );
            return false;
        }
        if &self.t1 > q7 {
            warn!(LOGGER, "ProofBob: check t1 < q7";
                "t1" => %(&self.t1),
                "q7" => %q7,
            );
            return false;
        }

        // 1-2. e'
        let e = {
            let list = xu
                .map(|(x, u)| {
                    let (xp_x, xp_y) = ecdsa::point_xy(x);
                    let (up_x, up_y) = ecdsa::point_xy(u);
                    [
                        pk.n().clone(),
                        pk.n().clone() + 1_u8,
                        xp_x,
                        xp_y,
                        c1.clone(),
                        c2.clone(),
                        up_x,
                        up_y,
                        self.z.clone(),
                        self.z_prm.clone(),
                        self.t.clone(),
                        self.v.clone(),
                        self.w.clone(),
                    ]
                    .to_vec()
                })
                .unwrap_or_else(|| {
                    [
                        pk.n().clone(),
                        pk.n().clone() + 1_u8,
                        c1.clone(),
                        c2.clone(),
                        self.z.clone(),
                        self.z_prm.clone(),
                        self.t.clone(),
                        self.v.clone(),
                        self.w.clone(),
                    ]
                    .to_vec()
                });
            let hash = hash_sha512_256i_tagged(&param.session, &list);
            &hash.rejection_sample(q)
        };

        // 4.
        if xu.into_iter().any(|(x, u)| {
            let e = ecdsa::to_scalar::<C>(e);
            let s1 = ecdsa::to_scalar::<C>(&self.s1);
            C::ProjectivePoint::mul_by_generator(&s1)
                != (C::ProjectivePoint::from(x.to_owned()) * e + u)
        }) {
            warn!(LOGGER, "ProofBob: check x * e + u == s1 * G");
            return false;
        }

        let mod_n_tilde = ModInt::new(n_tilde);

        // 5.
        if mod_n_tilde.mul(
            &mod_n_tilde.pow(h1, &self.s1),
            &mod_n_tilde.pow(h2, &self.s2),
        ) != mod_n_tilde.mul(&mod_n_tilde.pow(&self.z, e), &self.z_prm)
        {
            warn!(LOGGER, "ProofBob: check z^e * z_prm == h1^s1 * h2^s2";
                "z" => %(&self.z),
                "z_prm" => %(&self.z_prm),
                "h1" => %h1,
                "h2" => %h2,
                "s1" => %(&self.s1),
                "s2" => %(&self.s2),
                "e" => %e,
            );
            return false;
        }

        // 6.
        if mod_n_tilde.mul(
            &mod_n_tilde.pow(h1, &self.t1),
            &mod_n_tilde.pow(h2, &self.t2),
        ) != mod_n_tilde.mul(&mod_n_tilde.pow(&self.t, e), &self.w)
        {
            warn!(LOGGER, "ProofBob: check t^e * w == h1^t1 * h2^t2";
                "t" => %(&self.t),
                "w" => %(&self.w),
                "h1" => %h1,
                "h2" => %h2,
                "t1" => %(&self.t1),
                "t2" => %(&self.t2),
                "e" => %e,
            );
            return false;
        }

        // 7.
        {
            let mod_n2 = ModInt::new(n2);
            let left = mod_n2.mul(
                &mod_n2.mul(&mod_n2.pow(c1, &self.s1), &mod_n2.pow(&self.s, pk.n())),
                &mod_n2.pow(&(pk.n() + 1_u8), &self.t1),
            );
            let right = mod_n2.mul(&mod_n2.pow(c2, e), &self.v);
            if left != right {
                warn!(LOGGER, "ProofBob: check c1^s1 * s^n * (n + 1)^t1 == c2^e * v";
                    "left" => %left,
                    "right" => %right,
                );
                return false;
            }
        };

        true
    }
}

impl TryFrom<&[&Bytes; ProofBob::NUM_PARTS]> for ProofBob {
    type Error = CryptoError;

    fn try_from(value: &[&Bytes; ProofBob::NUM_PARTS]) -> Result<Self> {
        Ok(ProofBob {
            z: to_biguint(value[0])?,
            z_prm: to_biguint(value[1])?,
            t: to_biguint(value[2])?,
            v: to_biguint(value[3])?,
            w: to_biguint(value[4])?,
            s: to_biguint(value[5])?,
            s1: to_biguint(value[6])?,
            s2: to_biguint(value[7])?,
            t1: to_biguint(value[8])?,
            t2: to_biguint(value[9])?,
        })
    }
}

impl<C> ProofBobWC<C>
where
    C: CurveArithmetic,
{
    pub fn new(
        param: &ParamOfProofBob,
        xy: &(BigUint, BigUint),
        r: &BigUint,
        point: &C::AffinePoint,
    ) -> Result<Self>
    where
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        Self::create(param, xy, r, Some(point))
    }

    fn create(
        param: &ParamOfProofBob,
        (x, y): &(BigUint, BigUint),
        r: &BigUint,
        point: Option<&C::AffinePoint>,
    ) -> Result<Self>
    where
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let h1 = &param.n_tilde.v1;
        let h2 = &param.n_tilde.v2;
        let c1 = &param.c1;
        let c2 = &param.c2;
        let n_tilde = &param.n_tilde.n;
        let pk = &param.pk;
        let n2 = &pk.n().pow(2);
        let q = &ecdsa::curve_n::<C>();
        let q3 = &q.pow(3);
        let q7 = &(q3.pow(2) * q);

        let q_n_tilde = &(q * n_tilde);
        let q3_n_tilde = &(q3 * n_tilde);

        // steps are numbered as shown in Fig. 10, but diverge slightly for Fig. 11
        // 1.
        let alpha = &get_random_positive_int(q3).map_err(CryptoError::from)?;

        // 2.
        let rho = &get_random_positive_int(q_n_tilde).map_err(CryptoError::from)?;
        let sigma = &get_random_positive_int(q_n_tilde).map_err(CryptoError::from)?;
        let tau = &get_random_positive_int(q3_n_tilde).map_err(CryptoError::from)?;

        // 3.
        let rho_prm = &get_random_positive_int(q3_n_tilde).map_err(CryptoError::from)?;

        // 4.
        let beta = &get_random_positive_relatively_prime_int(pk.n()).map_err(CryptoError::from)?;
        let gamma = &get_random_positive_int(q7).map_err(CryptoError::from)?;

        // 5.
        let u = ecdsa::generate_mul::<C>(alpha);

        // 6.
        let mod_n_tilde = ModInt::new(n_tilde);
        let z = mod_n_tilde.mul(&mod_n_tilde.pow(h1, x), &mod_n_tilde.pow(h2, rho));

        // 7.
        let z_prm = mod_n_tilde.mul(&mod_n_tilde.pow(h1, alpha), &mod_n_tilde.pow(h2, rho_prm));

        // 8.
        let t = mod_n_tilde.mul(&mod_n_tilde.pow(h1, y), &mod_n_tilde.pow(h2, sigma));

        // 9.
        let pk_gamma = &(pk.n() + 1_u8);
        let mod_n2 = ModInt::new(n2);
        let v = {
            let a = &mod_n2.pow(c1, alpha);
            let b = &mod_n2.pow(pk_gamma, gamma);
            let c = &mod_n2.pow(beta, pk.n());
            mod_n2.mul(&mod_n2.mul(a, b), c)
        };

        // 10.
        let w = mod_n_tilde.mul(&mod_n_tilde.pow(h1, gamma), &mod_n_tilde.pow(h2, tau));

        // 11-12. e'
        let e = {
            let list = point
                .map(|point| {
                    let (px, py) = ecdsa::point_xy(point);
                    let (ux, uy) = ecdsa::point_xy(&u);
                    [
                        pk.n().clone(),
                        pk_gamma.clone(),
                        px,
                        py,
                        c1.clone(),
                        c2.clone(),
                        ux,
                        uy,
                        z.clone(),
                        z_prm.clone(),
                        t.clone(),
                        v.clone(),
                        w.clone(),
                    ]
                    .to_vec()
                })
                .unwrap_or_else(|| {
                    [
                        pk.n().clone(),
                        pk_gamma.clone(),
                        c1.clone(),
                        c2.clone(),
                        z.clone(),
                        z_prm.clone(),
                        t.clone(),
                        v.clone(),
                        w.clone(),
                    ]
                    .to_vec()
                });
            let hash = hash_sha512_256i_tagged(&param.session, &list);
            &hash.rejection_sample(q)
        };

        // 13.
        let mod_n = ModInt::new(pk.n());
        let s = mod_n.mul(&mod_n.pow(r, e), beta);

        // 14.
        let s1 = e * x + alpha;

        // 15.
        let s2 = e * rho + rho_prm;

        // 16.
        let t1 = e * y + gamma;

        // 17.
        let t2 = e * sigma + tau;

        let bob = ProofBob {
            z,
            z_prm,
            t,
            v,
            w,
            s,
            s1,
            s2,
            t1,
            t2,
        };
        Ok(Self { bob, u })
    }

    pub fn verify(&self, param: &ParamOfProofBob, x: &C::AffinePoint) -> bool
    where
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        self.bob.verify_with_wc::<C>(param, Some((x, &self.u)))
    }
}

impl<C> TryFrom<&[&Bytes; ProofBob::NUM_PARTS_WITH_POINT]> for ProofBobWC<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    type Error = CryptoError;

    fn try_from(value: &[&Bytes; ProofBob::NUM_PARTS_WITH_POINT]) -> Result<Self> {
        let bob = ProofBob::try_from(&[
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            value[8], value[9],
        ])?;
        let x = to_biguint(value[10])?;
        let y = to_biguint(value[11])?;
        let u = ecdsa::xy_point::<C>(&x, &y).ok_or(CryptoError::message_malformed())?;
        Ok(Self { bob, u })
    }
}

fn to_biguint(bs: &Bytes) -> Result<BigUint> {
    if bs.is_empty() {
        Err(CryptoError::message_malformed())
    } else {
        Ok(BigUint::from_bytes_be(bs))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::paillier::PublicKey;
    use k256::Secp256k1;
    use num_bigint::RandBigInt;
    use rand::RngCore;
    use std::ops::Mul;
    use std::str::FromStr;

    fn to_bitint(src: &str) -> BigUint {
        BigUint::from_str(src).unwrap()
    }

    #[derive(Clone)]
    struct Param {
        bob: ParamOfProofBob,
        xy: (BigUint, BigUint),
        r: BigUint,
        point: <Secp256k1 as CurveArithmetic>::AffinePoint,
    }

    impl Param {
        fn change_session(&self) -> Param {
            let mut bs = self.bob.session.to_vec();
            bs.reverse();
            let mut result = self.clone();
            result.bob.session = bs.into();
            result
        }

        fn change_pk(&self) -> Param {
            let n = self.bob.pk.n();
            let mut result = self.clone();
            result.bob.pk = PublicKey::new(n + 10u8);
            result
        }

        fn change_ntilde_n(&self) -> Param {
            let n = &self.bob.n_tilde.n;
            let mut result = self.clone();
            result.bob.n_tilde.n = n + 10u8;
            result
        }

        fn change_ntilde_v1(&self) -> Param {
            let v1 = &self.bob.n_tilde.v1;
            let mut result = self.clone();
            result.bob.n_tilde.v1 = v1 + 10u8;
            result
        }

        fn change_ntilde_v2(&self) -> Param {
            let v2 = &self.bob.n_tilde.v2;
            let mut result = self.clone();
            result.bob.n_tilde.v2 = v2 + 10u8;
            result
        }

        fn change_c1(&self) -> Param {
            let mut result = self.clone();
            result.bob.c1 = &self.bob.c1 + 10u8;
            result
        }

        fn change_c2(&self) -> Param {
            let mut result = self.clone();
            result.bob.c2 = &self.bob.c2 + 10u8;
            result
        }

        fn change_point(&self) -> Param {
            let another = (&self.point).mul(&ecdsa::to_scalar::<Secp256k1>(&BigUint::from(10u8)));
            let mut result = self.clone();
            result.point = another.to_affine();
            result
        }

        fn gen() -> Param {
            const BITS: u64 = 2048;
            let mut rnd = rand::thread_rng();
            let mut bs = [0_u8; 32];
            rnd.fill_bytes(&mut bs);
            let session = Bytes::from(bs.to_vec());
            let pk = paillier::PrivateKey::generate(BITS).public_key().to_owned();

            let q = ecdsa::curve_n::<Secp256k1>();
            let q5 = &q.pow(5);
            let beta_prm = rnd.gen_biguint_below(q5);
            let ct = pk.encrypt(&beta_prm).unwrap();
            let b = rnd.gen_biguint_below(&q);

            let n_tilde = NTildei::generate_for_test()[0].to_owned();
            let c1 = pk.encrypt(&rnd.gen_biguint_below(pk.n())).unwrap().cypher;
            let c2 = pk.homo_add(&pk.homo_mult(&b, &c1), &ct.cypher);
            let bob = ParamOfProofBob {
                session,
                pk,
                n_tilde,
                c1,
                c2,
            };
            let point = ecdsa::generate_mul::<Secp256k1>(&b);
            Param {
                bob,
                xy: (b, beta_prm),
                r: ct.randomness,
                point,
            }
        }

        fn sample_ok() -> Param {
            Param {
            bob: ParamOfProofBob {
                session: Bytes::from("session"),
                pk: PublicKey::new(to_bitint("24261589004465272731249327803101071103792958802723210985329987798404286346832084145379821062390362511363592469465551036623716847742366801146734075048032103335288069058682991894283824242201941990356426107676283864045055933692254494542670287211729114434164797753179698775293789682407290565454766674083988564005545698061330433346903087394170496980007835487898180646656591606889559906608994560791838505934557241218559133947318663171630480041559848077544934775873477027858500504325199526168809286442772506257956278830238227308912498225476420365415416389640465904626483958374392724811019844436417721814708231141829835974781")),
                n_tilde: NTildei {
                    n: to_bitint("25107490776052945575790163886980744121852075793230702092031092910315419013111724585107741342302647097816029689069156500419649067226989207335403141846585589456214707140363806918024254341805807847344462552372749802373561411623464018306841140152736878126807643286464707464144491205717529334857128642937311664356950670200785184493082292988908234459722618881044613550904554507333793627844968327344517418351075665978629614435510466378211576459017353838583039397930178040557511540818370302033808216608330168909665648805527673068950251148153088673193641290377199021831923470431364077200419352774733381328839199321622201645277"),
                    v1: to_bitint("947268510305326446073634507724913447936734171636912400557401318775427643035322780043344044871778218536295489345747992085537349997385753459769909944243608187249295932620582767525243046024431872134558350124222211815956076009495579000118546531817489783543950708796804986346442485595844139040615169351977594594085460608932273701244091036215057114383266995365365226626217411088112095883376367775475107954293975266374705057036496941779873360807750450088301028537780564210964889218799820623451941121168857520561736570209171665676631521362739174866629364755585577716299287494251706261472512421959632149833106509542229972234"),
                    v2: to_bitint("369382535766024782757053511943484023707590301248858510505619543451105355366349475321600848828578055383112252081262740450957242693258711711573898608872557215737850380375149487180022863563616178163440683814662347260503803753150609907077552201623376131096249150783552367189222999632342102603491398593162398739317344334427947844029843540621897547082716967267285286086227255034044222917612280937408214149645699005643727644027239999997789724357422423935120674874708262799420509411969660535187315093553065000790565517535769427338692918882249946664488170641583406635227373502217028982923125561321182147198392699754510926843"),
                },
                c1: to_bitint("400188980994774655609968091936620060124194780418395642324023940691239945255312247610992811612431249936152054069340910452935275205487424854634246828482246352144337182419040538212228852534225304174368343947023564538801615828687299316803241803369288485506946718273947431531973813858828408905751899378227757543579871688504974553109136356994904735037599168566303793641249248025873904193154372979358251360874998196205783452661730986829472793946270963339861788192770799371305531044326953375551834910629477333425892458792662376368650895554603125094896843040198744699366418823291775347326054231834531358977230768426742453712318682737791792820647755652215856663778772847375042277205326803580443908810548115875614952826259458257258493697853793646331037887120817707513503571379434818731866933591449738884942230286964560975261495708985005280778505293251103037083314378974282722058952927812473759779022197254469017388422994057180505540627929700170170320971992028762205724059261013866722334225838238320698563687792441899338330349607215301028623539836617463866851633411657797882767517790720192752726498897268976870434440522723184905076615752830635734406782805309804373897258628489152609956916649503127542627206201799628788404190292045079845695539005"),
                c2: to_bitint("98573216923670029482821115497694158997701755867518675487809563002262969374429334440082681941600401097934556988790183729523580720309003894174143686603097011750180621654263582730257639883377054326574168737200415168109016934596056214113130498173847556339154501370028792265841294296659920063110922540964643954044560558816019775357577881424654115472796241983478183026500401778150566430093557176244961750759228035574132175895475959282423213068981255863315840431505638769681064902513786237796323681661253900688171694813024684962553099575687213643953866670007212555321378763872102032075258716404994287465655087264659390259026908282688806618224771400409708056097235104949067246227149153871512407333953827944360034115190003167379402652418218088558623986757262384661381181534752894246084721691776580316855378370830325218479465488778739115168862573546202079589373938148889660862603212262415001010351315286539400994916127576235285929134852940474957058813438546566643450052998120855803755264759031202653355459212026268818145535080517620144856445898319577455911245421862936535731411912720397377403186779885488966511055963605408874871060573451766442775230526695777998996381124371051298228555236557500794840592492822277944138084212794148491560062194"),
            },
            xy: (
                to_bitint("20872918044507599492457919043155243332921084283187084425223278835323345316707"),
                to_bitint("13365803136768827314472359487832734942388024092573771842356564480371273430093788764148177649590147601079991374084731619027142332042824767083157035176876340102099960663493606582967420224789162175044870543176867902664052695037517942038248013816833256471600451521497813841165600589598039533465498062819816581880369639821378040565954040957506700021927229986652022091615738614219190677069635"),
                ),
            r: to_bitint("21617745718658475423967690137755260260751176145758099656379627827529447465873941447558271433560154929175996297478257677991009360164924302078973592231666628498979499849260499718709195852482305685149481840993520270133375205592174152961925586484451711506799685098224993369966535853381357250207917204040666031452544422143667110446801956906625901747974275844240807779974858102640852085251773464817602345912999959784397499248630936345359919089789880396555926854044371853388456300266725449255410786594189679918897998146392256946271699268332250404359035739120314312721689120835606374439344529292527051773663149198509109589298"),
            point: ecdsa::xy_point::<Secp256k1>(
                &to_bitint(
                    "104639075809233846840558005847879026027812042860709851555234497260916054215660",
                ),
                &to_bitint(
                    "75893047884391164204942577163850331696590636042088436736848678939010438699885",
                ),
            )
            .unwrap(),
        }
        }

        fn sample_proofbobwc() -> ProofBobWC<Secp256k1> {
            let bob = ProofBob {
            z: to_bitint("24087427653130783300806441355109716312566707292282876281751843367924485397267296166226333837980147656580024839218091362776604955450435885362363529603930282514164646618607666162163851499485188840016252531064227930004793540822440718287994844602118345542457264914086915723296810713846018481648182555668300304623808483135645918411446883928621654077134893653660832334879212407926036660378765854963793892226828954852544081361418121959281101934489856465254653948821796914783207599718012945352178049761986525795686711051470606377254238824634418830555475308116657708624276483597193661371723781739126904881992464002593840127403"),
            z_prm: to_bitint("15314560553259470083844690925205061655526407186943965922974380757246303818062028766314974883757493540952768962245214753073114140962015434688062081925469255524685527678662835129230683333302333402630914416476313312152726529612347853271118086065773867950455244446467705250924659323103673350457556400308296769299966404549355711354540435469715282112027958365969024015647159691224243131988510407827248323735900527382865773681931633269285033226737479118350074150642319605325057973312542237937861691878916693588454715903033556350500198599378899094298426193443040743397109601871308809234294669352031099046306225807475963324722"),
            t: to_bitint("5490822757340167215655393482816214849985060789282500887927811891062085975038244802511199786773291410796675495239850493751837133846152849765777077000708445432608448922299800103464528135916292389415793323027827707083105527683323603963290206578573414210974168749361987088484873890156777577734361778620289788164371107502204917894235413860033847373171516402558059378411542483640498144434052088654198686508460687957450033419597051640514021984346310956930398689405506708709287958982919175619482358685448784485435439275452641138741409218356011861912247493157063493823920622457454245043716551256148011385561405763787178481663"),
            v: to_bitint("153738904531326835279627313179816555252554762709832957489950123595089738145422194685072453151773925866456697412125302280039732936093956160055457509543682188412343358236971630545267840628702289720829747562370536288368284726845800709065460168982630136942028934890974730920692630603544629765023412799711600213454289232722852939990491469944402421698472431740035390136884675773009618990284371484577489910182343745022607759960187301215897076168666674982232939778992213269339530330985246143866944640448297430476678947782605091966811087476366322799475406945240224274729259937270585898852126501676591636265993118733632881744921040671207392302321864170126895932966766423664066247307211521895668856394118937080303939189662789678177619188435576832168914166020760141689330619775425692533516356392594125748830645230874542512867229885911512073525210675061262556425724609455006456727382608643239314506534423831780789880806921801429136776465950287757967863232594461720030696219542451498376560067370150809441893600295305834082118057203247644581760817603757875176652447985607814909108824061421959809677536458717600027424524256271677669205284484358734209264991296090477819017589214373187920007309009188376737626824538888283395698404243551127963412776155"),
            w: to_bitint("20874264187862111314846477068266233861981459790454655804247967941031780606130294397389963870183383295327092733481366424090053751919130342462279431727337256089414566811986263340392333782313555022316505409804795907828575790107458415208131636091441349687388976010132793525101294601684622550850294358167376281740825694161275815398738872234953825829684918006026251856934280801782748340289623178872338605716772810059408903147512523702349032990500766338744779943404067967452687700982577803313341958708386057178993668932915952929681503781322223677236313421183705012646173680895469504020569510192978147884829548137810866142189"),
            s: to_bitint("18315639515348148052099932526496946739323352501314595602232625534337963448525328865797567640968404959588711422500737938678366389374648253053310197693187550332269557823182844287173852545292874082950535103612003089453652096249049193956253468008843686401861725072706406484499718696651956732422692226391613684992632064959915818554403132461153091622500758685423900817087637219120502773986063913371061858824421986833696815601321382962562288201628422419073705018094361080832067055250412927740955017026955855786200003073066957245567821613797102821519928628966247361391929901792856385444346349404931048747234351108036505717247"),
            s1: to_bitint("1184835270474561755072967573223361200688582211478811532104499153983832686186412487802868719682859790292810770169375308560960994080988517025714854121905275469728029451396624075597343977993668447681954676388144288541402186119400296181"),
            s2: to_bitint("17890329211346771266346427451355508614329283177576742629812752664419418919953870482089057125551010728177271026711801310687757260125969167976231086629256446693810558449208332789468053561443465959166795875781844079094832060130268660687382570507043354878714481501134851021759485217626299547936179586975059823667201929418344331118651847333420110263545015156695198064614544131370199091361288138449754087470804616763474228385300505402074725919829414601213492940689370032263516882775222710647272435681910814924775631739533684804723866349283707685784872439112917070951133050268184975286550058713968425100406524710727495282249246041410134657747234796593147595374644163890827271300669244564989217066310048700317359160863100569330642792184802147204657470094616309952842560753940059569041522684603635926728174282007437130147499581621926784496417897258680659565"),
            t1: to_bitint("241280941203235534497056671419172369125396075048088326560340002583590069077774789413299676940713501724223682268218587256272969043696385300880828445774312275022344638222393383648134232760383003766573730211593285538693635244483735904550689061283570530583412613821613571319510502180750579679204545475346199787124779133030796897712360976276513351311008039838292710813278938595742379503977217911468050574216629705947475646683051197855660290699263383390256260270778782019015917145932571661784500375861697839394190887041425358381711064013608938104"),
            t2: to_bitint("23784264066693626668033541499289030274760298379501222463861143901094062883888722222334760116278775612045605750598494001341314633654810315770936195635588382388163652576668297435802448907729165496458988098158251332183199336421945052290772362321817002849714994291244021948308207054824439599861170501624048240669858036271392793024702118097818515610537074102610503759651429997806408269708453048915801293438647226992455300925559035917085447079558015705599868097826811860114778414742785873541843138057742377806248637333252979270235281217526496258526434658005637193654693052538292713578150947561554011579801432556861500384603707599373494745127662009831498248591656841914112511915038346849491746711226433576649966832433869034488377311855157098593549117146378911165683777560683621958814276321516353420191571777880917866916200391902660823231821005410014858460"),
        };
            let u = ecdsa::xy_point::<Secp256k1>(
                &to_bitint(
                    "26912176195937656799074909697683894692875994042607636514258856596484785845540",
                ),
                &to_bitint(
                    "24483982419552029276200311093164617688934683479659796551066895686587467398447",
                ),
            )
            .unwrap();
            ProofBobWC { bob, u }
        }
    }

    #[test]
    fn proofbobwc_verify() {
        let param = Param::sample_ok();
        let proofbobwc = Param::sample_proofbobwc();
        assert!(proofbobwc.verify(&param.bob, &param.point))
    }

    #[test]
    fn proofbob_by_sample() {
        let count = 10;
        let param = Param::sample_ok();
        for _ in 0..count {
            let proof_new = ProofBob::new::<Secp256k1>(&param.bob, &param.xy, &param.r);
            assert!(proof_new.is_ok());
            let proofbob = proof_new.unwrap();
            assert!(proofbob.verify::<Secp256k1>(&param.bob))
        }
    }

    fn loop_proofbobwc_new_and_verify(param: &Param, count: u8) {
        for _ in 0..count {
            let proof_new = ProofBobWC::new(&param.bob, &param.xy, &param.r, &param.point);
            assert_eq!(None, proof_new.clone().err());
            let proofwc: ProofBobWC<Secp256k1> = proof_new.unwrap();

            let verify = |p: &Param| proofwc.verify(&p.bob, &p.point);

            assert!(verify(param));

            assert!(!verify(&param.change_session()));
            assert!(!verify(&param.change_pk()));
            assert!(!verify(&param.change_ntilde_n()));
            assert!(!verify(&param.change_ntilde_v1()));
            assert!(!verify(&param.change_ntilde_v2()));
            assert!(!verify(&param.change_c1()));
            assert!(!verify(&param.change_c2()));
            assert!(!verify(&param.change_point()));
        }
    }

    #[test]
    fn proofbobwc_by_sample() {
        loop_proofbobwc_new_and_verify(&Param::sample_ok(), 10)
    }

    #[test]
    fn proofbobwc_by_gen() {
        loop_proofbobwc_new_and_verify(&Param::gen(), 10)
    }
}
