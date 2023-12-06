use crate::hash::hash_sha512_256;
use crate::utils::ecdsa::point_xy;
use crate::{CryptoError, Result};
use common::mod_int::ModInt;
use common::prime::GermainSafePrime;
use common::random::{get_random_positive_relatively_prime_int, is_number_in_multiplicative_group};
use elliptic_curve::sec1::{ModulusSize, ToEncodedPoint};
use elliptic_curve::{Curve, FieldBytesSize};
use num_bigint::BigUint;
use num_integer::Integer;
use num_modular::{ModularPow, ModularUnaryOps};
use num_traits::{One, ToPrimitive};
use rayon::prelude::*;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PublicKey {
    n: BigUint,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PrivateKey {
    public_key: PublicKey,
    p: BigUint, // p > q
    q: BigUint,
    phi_n: BigUint,    // (p-1)(q-1)
    lambda_n: BigUint, // lcm(p-1, q-1)
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub cypher: BigUint,
    pub randomness: BigUint,
}

pub struct Proof([BigUint; Proof::ITERATION]);

impl Proof {
    const ITERATION: usize = 13;

    pub fn new<A, C>(key: &PrivateKey, k: &BigUint, point: &A) -> Self
    where
        A: ToEncodedPoint<C>,
        C: Curve,
        FieldBytesSize<C>: ModulusSize,
    {
        let xs = Self::generate_xs(key.public_key(), k, point);
        let ys: Vec<_> = xs
            .iter()
            .map(|x| {
                let m = key.n().invm(&key.phi_n).unwrap();
                x.powm(&m, key.n())
            })
            .collect();
        Self(ys.try_into().unwrap())
    }

    pub fn verify<A, C>(&self, pubkey: &PublicKey, k: &BigUint, point: &A) -> bool
    where
        A: ToEncodedPoint<C>,
        C: Curve,
        FieldBytesSize<C>: ModulusSize,
    {
        let n = pubkey.n();
        let xs = Self::generate_xs(pubkey, k, point);
        self.0.par_iter().zip(xs.par_iter()).all(|(y, x)| {
            let a = x % n;
            let b = y.powm(n, n);
            a == b
        })
    }

    fn generate_xs<A, C>(pubkey: &PublicKey, k: &BigUint, point: &A) -> [BigUint; Self::ITERATION]
    where
        A: ToEncodedPoint<C>,
        C: Curve,
        FieldBytesSize<C>: ModulusSize,
    {
        let (x, y) = point_xy(point);

        Self::generate_xs_by_xy(pubkey.n(), k, (&x.to_bytes_be(), &y.to_bytes_be()))
    }

    fn generate_xs_by_xy(
        n: &BigUint,
        k: &BigUint,
        (xb, yb): (&[u8], &[u8]), // in big-endian
    ) -> [BigUint; Self::ITERATION] {
        let kb = &k.to_bytes_be();
        let nb = &n.to_bytes_be();
        let blocks = ((n.bits() as f64) / 256.0).ceil().to_usize().unwrap();

        let to_bs = |i: usize| i.to_string().as_bytes().to_vec();

        let mut t = 0;
        let xs: Vec<_> = (0..Self::ITERATION)
            .map(|i| {
                let ib = &to_bs(i);
                (t..)
                    .find_map(|ti| {
                        t = ti;
                        let tb = &to_bs(t);
                        let bs: Vec<_> = (0..blocks)
                            .into_par_iter()
                            .flat_map(|j| {
                                let jb = &to_bs(j);
                                let hash = hash_sha512_256(&[ib, jb, tb, kb, xb, yb, nb]);
                                hash.as_ref().to_vec()
                            })
                            .collect();
                        let x = BigUint::from_bytes_be(&bs);
                        is_number_in_multiplicative_group(n, &x).then_some(x)
                    })
                    .unwrap()
            })
            .collect();

        xs.try_into().unwrap()
    }
}

impl PrivateKey {
    const PQ_BIT_LEN_DIFFERENCE: u64 = 3;

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn p(&self) -> &BigUint {
        &self.p
    }

    pub fn q(&self) -> &BigUint {
        &self.q
    }

    pub fn n(&self) -> &BigUint {
        self.public_key.n()
    }

    pub fn generate(mudulus_bit_len: u64) -> Self {
        let (p, q) = Self::gen_pq(mudulus_bit_len / 2);
        let n = &p * &q;
        let q_1 = &q - 1_u8;
        let p_1 = &p - 1_u8;
        let phi_n = &p_1 * &q_1;
        let lambda_n = &phi_n / &p_1.gcd(&q_1);

        Self {
            public_key: PublicKey { n },
            p,
            q,
            phi_n,
            lambda_n,
        }
    }

    fn gen_pq(bit_len: u64) -> (BigUint, BigUint) {
        let min_sub = bit_len - Self::PQ_BIT_LEN_DIFFERENCE;
        const CONCURRENT_NUM: usize = 100;
        (0..)
            .find_map(|_| {
                (0..CONCURRENT_NUM)
                    .into_par_iter()
                    .map(|_| {
                        let p = GermainSafePrime::generate(bit_len).safe_prime;
                        let q = GermainSafePrime::generate(bit_len).safe_prime;
                        if p > q {
                            (p, q)
                        } else {
                            (q, p)
                        }
                    })
                    .find_any(|(p, q)| (p - q).bits() >= min_sub)
            })
            .unwrap()
    }

    pub fn decrypt(&self, c: &BigUint) -> Result<BigUint> {
        let n2 = ModInt::new(&(self.n() * self.n()));
        if c >= n2.module() {
            return Err(CryptoError::message_too_long());
        }
        if c.gcd(n2.module()) > One::one() {
            return Err(CryptoError::message_malformed());
        }

        let lcalc = |a| -> BigUint {
            let x = n2.pow(a, &self.lambda_n) - 1_u8;
            x / self.n()
        };

        let lc = lcalc(c);
        let lg = lcalc(&(self.n() + 1_u8));
        let mod_n = ModInt::new(self.n());
        let inv = mod_n.mod_inverse(&lg)?;
        Ok(mod_n.mul(&lc, &inv))
    }
}

impl PublicKey {
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    pub fn encrypt(&self, m: &BigUint) -> Result<EncryptedMessage> {
        let n = self.n();
        if m >= n {
            return Err(CryptoError::message_too_long());
        }
        let x = get_random_positive_relatively_prime_int(n)?;
        let n2 = ModInt::new(&(n * n));
        let gm = n2.pow(&(n + 1_u8), m);
        let xn = n2.pow(&x, n);
        let c = n2.mul(&gm, &xn);
        Ok(EncryptedMessage {
            cypher: c,
            randomness: x,
        })
    }

    pub fn homo_mult(&self, m: &BigUint, c1: &BigUint) -> BigUint {
        let m = m % self.n();
        let mod_n2 = ModInt::new(&self.n().pow(2));
        let c1 = c1 % mod_n2.module();
        mod_n2.pow(&c1, &m)
    }

    pub fn homo_add(&self, c1: &BigUint, c2: &BigUint) -> BigUint {
        let mod_n2 = ModInt::new(&self.n().pow(2));
        let c1 = c1 % mod_n2.module();
        let c2 = c2 % mod_n2.module();
        mod_n2.mul(&c1, &c2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::prime::miller_rabin::is_prime;
    use elliptic_curve::point::DecompressPoint;
    use elliptic_curve::subtle::Choice;
    use k256::ecdsa::signature::digest::generic_array::sequence::GenericSequence;
    use k256::AffinePoint;
    use k256::FieldBytes;
    use num_bigint::RandBigInt;
    use rand::Rng;
    use std::str::FromStr;

    #[test]
    fn private_key_generate() {
        const BIT_LEN: u64 = 512;
        let sk = PrivateKey::generate(BIT_LEN * 2);
        assert!(is_prime(&sk.p, None));
        assert!(is_prime(&sk.q, None));
        assert_eq!(sk.p.bits(), BIT_LEN);
        assert_eq!(sk.q.bits(), BIT_LEN);
        assert_ne!(sk.p, sk.q);
        assert!((&sk.p - &sk.q).bits() >= BIT_LEN - PrivateKey::PQ_BIT_LEN_DIFFERENCE);
        assert_eq!(sk.public_key.n, &sk.p * &sk.q);
        assert_eq!(sk.phi_n, (&sk.p - 1_u8) * (&sk.q - 1_u8));
    }

    #[test]
    fn encrypt_decrypt() {
        const BIT_LEN: u64 = 512;
        let sk = PrivateKey::generate(BIT_LEN * 2);
        let mut rnd = rand::thread_rng();
        let mut m = rnd.gen_biguint(BIT_LEN);
        m.set_bit(BIT_LEN - 1, true);
        let encrypted = sk.public_key.encrypt(&m).unwrap();
        let m2 = sk.decrypt(&encrypted.cypher).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn encrypt_failure() {
        const BIT_LEN: u64 = 128;
        let sk = PrivateKey::generate(BIT_LEN * 2);
        let m = BigUint::one() << (BIT_LEN * 2);
        assert!(sk.public_key.encrypt(&m).is_err());
    }

    #[test]
    fn proof_verify() {
        const BIT_LEN: u64 = 512;
        let sk = PrivateKey::generate(BIT_LEN * 2);

        for _ in 0..100 {
            let mut rnd = rand::thread_rng();
            let k = rnd.gen_biguint(BIT_LEN);

            let point: AffinePoint = (0..)
                .find_map(|_| {
                    let x = FieldBytes::generate(|_| rnd.gen());
                    AffinePoint::decompress(&x, Choice::from(0)).into()
                })
                .unwrap();
            let proof = Proof::new(&sk, &k, &point);
            assert!(proof.verify(&sk.public_key, &k, &point));
        }
    }

    #[test]
    fn par_order() {
        let src: &Vec<_> = &(0..100).collect();
        let expected: &Vec<_> = &(0..200).step_by(2).collect();
        assert_eq!(src.len(), expected.len());
        for _ in 0..100 {
            let dst: Vec<_> = src.into_par_iter().map(|x| x * 2).collect();
            assert_eq!(dst, expected.clone());
        }
    }

    #[test]
    fn generate_xs() {
        let k = BigUint::from_str(
            "51499585221787163116854575080451082823718895845307306514474968008279729297606",
        )
        .unwrap();
        let n = BigUint::from_str("24279512956040306869765035356250837035326639988655499855072509406238170948177485361751872286471079370216189691289236553356479163920369596892315971024489247019099031725030197112049184239517668626245115495656935207462826637117429407371550934046119778286308284346009614438229135404088526496472174820167957252153035305230999663867443901800896981827475634498238426946937326992868276155008889467500014563150556875900930377420286001211388841368172228313496707456524054429535686311045522670891415856274888893425961365489820956024158764698545338067851260726027696299141052801767390752057153608826743271242357161208739016301231").unwrap();
        let x = BigUint::from_str(
            "21762111281672183536884157469155231494542826056447421783132806364052076912532",
        )
        .unwrap();
        let y = BigUint::from_str(
            "39644684082436233593485507409442167155658462216074012439625636229226939269691",
        )
        .unwrap();

        let expected_xs: Vec<_> = [
            "10923995466766390689412321161997115647418040021101279955463290325323620411340928109657634098990778379192995783890549527930502589362595564125808653553041006300066527179672240906565471327612584723476845821493093981829417408938625783427509981370106727954779025573347070209525173893148980830713989063013977239444645663930351155657780252893486724954508717757299573004838898713473527451054764568658620773961186927683391958967898869144723041679606069190302802145993068907203977203325944704638599015831729648686612959770262290640332239646668309029501628730460832012242502869148931241147552767358334656820662284382835251157825",
            "15229831887500974735678429133540198439886153684803107437288004766268649238180912155682454288231965228541164383750738841710563547143694145109433643717664025896996006963142984329092283175778706510955235407808031311816398269325111621979758695513133122501837528568356314818492446179645105860210754946119959701518027950036628569911926107485461331402077779177318773159448813977486457779633290176463116465948297951947826382552087177492891062460529184521972225327127115036575496134584274471329727494152458658355639638212140588601884660496010829832279809541750898132880724064044435595989643526944444529685843720043693065862859",
            "21676852724404197495717413196746542779793684405724984433374752116670256246545955961268886766200035996166442763983093612157636914506760268408076349517241056295096923864438190307621359638782696259501617503205713307162347611732781347265230045076786886075816599739733725336249629570717111318196757655281420635254911854406108171982111439801846635021585258541756479472240364102904470220667717334728569014195854442640159146404546442340649686307948495808357091004979074812566678098193855072952514587070832162320759822416871147074751208156289652510283718721563671438857185039972199814371413578683745693095963634757425873785437",
            "24060498143347146440348991528605568850400091895248837441567974294180224366212403147269171811518942972531432059794996400738512576919276818351711176076902129530605131509656623809982004374690358455398790568237583776264822832137246768005042331507815788145020787542507022127540674986446260801053337724273341824997698260100288365938595939171202180337543656684535673234079504709694643365792713963051255253109289902522989359394554479130259650978673372883064241943515406915124197932752374225446063437959456630182496943082691750738069173129838190063043251222522128830323127890375137983384444475559591109642360260141837871499384",
            "18101443564088570875241661066075988670349885844686828821690800524982974507893662702480025191297962406487720649073822919480020922784882671041040611798917015231120161330508518794133775636196955246021494174938459333236175778245378879114564888649533322695691133245380180122641438729528561581628093095127673989125009277498071610129938486264973835277417510820620431260047439675065623229119868790358793581723624839007724498835664381790298982364701689576856038076049340859034135486281743175461560565613195864058066200025384063067086829186601671880302698382234088074849137211689172391708022928736439548935766261020955343610199",
            "13978616977421355590483198035079333066348715727766177174604371281033720674401072584394024987734795598537101702998284072232922199240747713999527543086885210789924581987349934764804846731352718533471957995080340865714182138625978118585335197496055384797266965364120660358939054565567971862951950931272380458276516756672325479023393233389356886804724623488492034290079715793965082569040526045972332972498047853194195589674140175381588712290938692409520812692446077058081362631142276230758644192777789616717602141377950161989062287480643418421058583948557301195336914278507715539019648374483581766102304569782840296601721",
            "23068640512696990614136054645491316561261377492591762147345627011458389670242570867279339688176177328234424262067976199192838395930039032416594597570572534492528736972545250680184788254174322400594822448042998046352574477265681238951227865441587001917944284362211729599679765027662550249749988956920511005279426147188808593117779797648509814801355604077722645124041312270477040893560317863104736643289474669102996722462098104164378643205573577417434278861459665807580280999925456644757796186731890259247710060779628231183843494927169623219944590210077569182475509266583946821399625534820436599068275584701488890645922", 
            "13644822539756677755898786092337354005744997150670090943538555298984553573157508637618810103994001910832318124421708875062064169813070817835963728356755724484906301071965279378592949280168590045054502134127069868887378323061100222680094949024001968458884754061000067454569133799537410974070234229758953888150585882472702584797192397498249782164493379451604771229675629298493337965562840939295462979075101757575252592150248364634425558550816367793676350842524784844756858117769854636361682851675986571795044230079155902845603741008075050021241361229481445319740954832100906759968327175948069728490638329792764546829308",
            "19745609489856892511302641717951368879817978143941842356499053995835587096180476804913959907856530560419457968447272323395680467129434845109785108750127063140260239607984761806998970562154042437810440658019630306983471999203653326793583828228531319778410842209352150097757121335043885604166781246666278970293326022058300738171445041923144758819150310195611119797598474816637558519445184909015150073282133626172271702875494505758763066252586150151858519303024805241267249450092788150509548359882270660461377523427882418291850682187289111173609307658457745796303108835234677011969228718474703999205333485051024555690280",
            "8483445946590293894629472557990851013530706685119589933620213805824526658665215563896729543714040708680734746733696742842241966816672791879424273312736160837349657311835136052870321768717683188952774853083650712097348021121729672018335706617855767022350118280118098714284031886754666387257891483673132845421575839043729243930337766504776171676792443154894189944664118797231049129121396442565681542635121788554966338671691582648551044917692902184300639445296726422782805542731233818772624223835218977834225748778906878835721600602356450997442732765247508102718968520043323995602444893947959895456070662421452909051821",
            "19505839260410294735042319118506710327728441666620024287667392672888284883194184026448450969904462677639047486327031469054463009032351340362619930172865270023511562271352412627919010414056723776615915445497931582936611179126837739039397810474353578037045114495978345234342663216353256595400602292178730970172627850977672441340602290837888926541713738118652752095920513519928441225688802821747035923510608570002359218037014859273380402020465497295071410761351306668326646465654367879726289815657204455550545734246985008765157091550039834549309824078708533929012566134024022091689877064948179989673827060966044179825965",
            "5452321119129956709868065458392652003787107832584676957731122868824538806700278910148262515921484703313737985545792252695898389781085111365107636541419783146586549882214766574791415570735956203691775888246583217726095040690726406781549749819392038395547039344133233013214995145000242034606862581948752602167219865552794372379408057543791215964740883940710282639509520972970319015592177187597554547387060119532823184864812585230031971391692368660867486086188259179343857591756579252483336735071480753159960817251396396420272894311053073909292266213311194571610811072642974028940156694295493809964787133767734008846758",
            "22770476443770469410468443835526959870571658440108523492659895291309004068866749148002145400383830705962349497556450408823877589907242651769796880313831328231280557584644214384115511978540095350852076434496078762079910163655621133350259292622322651862508243543942882842796244621624345721274052346520388560672956186051181738925366165677772185896341886710974504158632918144807175780932513615989734647038030575147734752041698108160159587312262176303779619044052068180522040222818214341775110330779426191435808162168504173921319002291723870733256038430810470241062781197101100633043157187885246168279953111555584543679920",
        ].iter().map(|s| BigUint::from_str(s).unwrap()).collect();
        let xs = Proof::generate_xs_by_xy(&n, &k, (&x.to_bytes_be(), &y.to_bytes_be()));
        assert!(xs
            .par_iter()
            .all(|x| is_number_in_multiplicative_group(&n, x)));
        assert_eq!(xs.to_vec(), expected_xs);
    }
}
