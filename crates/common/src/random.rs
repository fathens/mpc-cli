use crate::{CommonError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_modular::ModularSymbols;
use num_prime::nt_funcs::is_safe_prime;
use num_traits::{One, Zero};
use std::ops::RangeInclusive;

const RANDOM_BITS_RANGE: RangeInclusive<u64> = 1..=5000;

fn check_bits_range(bits: u64) -> Result<()> {
    if !RANDOM_BITS_RANGE.contains(&bits) {
        return Err(CommonError::out_of_range(bits, RANDOM_BITS_RANGE));
    }
    Ok(())
}

pub fn get_random_int(bits: u64) -> Result<BigUint> {
    check_bits_range(bits)?;

    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint(bits);
    Ok(r)
}

pub fn get_random_positive_int(ceiling: &BigUint) -> Result<BigUint> {
    check_bits_range(ceiling.bits())?;

    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint_below(ceiling);
    Ok(r)
}

pub fn get_random_prime_int(bits: u64) -> Result<BigUint> {
    check_bits_range(bits)?;

    let mut rnd = rand::thread_rng();
    let mut r = BigUint::zero();
    while r.is_zero() || !is_safe_prime(&r).probably() {
        r = rnd.gen_biguint(bits);
        r.set_bit(0, true);
    }
    Ok(r)
}

pub fn is_number_in_multiplicative_group(modulus: &BigUint, number: &BigUint) -> bool {
    !number.is_zero() && number < modulus && number.gcd(modulus).is_one()
}

pub fn get_random_positive_relatively_prime_int(modulus: &BigUint) -> Result<BigUint> {
    if modulus.is_zero() {
        return Err(CommonError::invalid_argument(
            modulus,
            "modulus must not be zero",
        ));
    }

    let mut r = BigUint::zero();
    while r.is_zero() || !is_number_in_multiplicative_group(modulus, &r) {
        r = get_random_positive_int(modulus)?;
    }
    Ok(r)
}

pub fn get_random_generator_of_the_quadratic_residue(modulus: &BigUint) -> Result<BigUint> {
    let f = get_random_positive_relatively_prime_int(modulus)?;
    let fsq = f.sqrt();
    Ok(fsq % modulus)
}

pub fn get_random_quadratic_non_residue(modulus: &BigUint) -> Result<BigUint> {
    if modulus.is_even() {
        Err(CommonError::invalid_argument(
            modulus,
            "modulus must be odd",
        ))?;
    }

    let mut r = BigUint::zero();
    while r.is_zero() || r.jacobi(modulus) >= 0 {
        r = get_random_positive_int(modulus)?;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;
    use std::str::FromStr;

    #[test]
    fn get_random_int_success() {
        let check = |bits: u64| {
            let r = get_random_int(bits).unwrap();
            let ceiling = BigUint::one() << bits;
            assert_eq!(
                true,
                r < ceiling,
                "r: {}, ceiling(bits): {}({})",
                r,
                ceiling,
                bits
            );
        };

        for bits in RANDOM_BITS_RANGE {
            for _ in 0..10 {
                check(bits);
            }
        }
    }

    #[test]
    fn get_random_int_failure() {
        let err = get_random_int(0).unwrap_err();
        assert_eq!(CommonError::out_of_range(0, RANDOM_BITS_RANGE), err);

        let err = get_random_int(5001).unwrap_err();
        assert_eq!(CommonError::out_of_range(5001, RANDOM_BITS_RANGE), err);
    }

    #[test]
    fn get_random_int_cap_success() {
        let check = |ceiling_bits: u32| {
            let ceiling = BigUint::one() << ceiling_bits;
            let r = get_random_positive_int(&ceiling).unwrap();
            assert_eq!(true, r < ceiling);
        };

        for ceiling_bits in 1..100 {
            for _ in 0..100 {
                check(ceiling_bits);
            }
        }
    }

    #[test]
    fn get_random_int_cap_failure() {
        let err = get_random_positive_int(&BigUint::zero()).unwrap_err();
        assert_eq!(CommonError::out_of_range(0, RANDOM_BITS_RANGE), err);
    }

    #[test]
    fn get_random_prime_int_success() {
        let check = |bits: u64| {
            let r = get_random_prime_int(bits).unwrap();
            assert_eq!(
                true,
                r.bits() <= bits,
                "r: {}({}), bits: {}",
                r,
                r.bits(),
                bits
            );
        };

        for _ in 0..10 {
            check(128);
        }
    }

    #[test]
    fn is_number_in_multiplicative_group_success() {
        let check = |a: &str, b: &str| {
            let modulus = BigUint::from_str(a).unwrap();
            let number = BigUint::from_str(b).unwrap();
            assert_eq!(
                true,
                is_number_in_multiplicative_group(&modulus, &number),
                "modulus: {}, number: {}",
                modulus,
                number
            );

            assert_eq!(
                false,
                is_number_in_multiplicative_group(&number, &modulus),
                "modulus: {}, number: {}",
                modulus,
                number
            )
        };

        check("173599091546016258478070275884420538425344432129693465943377243811455309900387734053435043582114630859932068598174971000459313735559048750110465385665544021403728463483972472430067887518798929793655675142110097368324534076057835853306465142345239675319343321622958142649153418220309035422496083822684984421644",
              "68318629383806310809205791680195169041105112547556504573876402438650147012653571976129434749537433239368497052000658722882097432473139051389339016469725220929223791452969884614346004336152861806892185978654506031990763986732822089149569178309451476133566844592345500475633459459230041543157482873328972077883");
        check("5592582363282202197543519483532170663022580806883045849912478778662524405778092858794812997316362404908545720496172674660069446912005309147222977821312254176330713846293219764126021814362953045900439868946468546769852132995313952982475534756086055827879350075503662958396782928391299397516820938157036370918",
              "3127651586020383410876903556824993431587732362690360952128882619837806897863190242987253449723721312775312438273834394017713552018600287509134011169529450921587165587769406313125434282364524925663105293217280086216394445794481461315263923712399315686509136808650640073501222346522305707574504762385678397315");
        check("146373604232153391803469037380895671707216766215052248848393164733874560787546188861639917529332414900977366776260011495170122198285074923066185186285152903095457529635635546584875776802992394344192527020423808164993865237422990455039261655390603773421944567170199337421424182231170477597040613014540441590853",
              "73814396558613031562404263198440009178044497939634999258631818787651099905315215197817283979847294172782919884130931343874757713050896272168972401047281865183292644706728547542257434927516476640760927606807238895355948417748080464638777119731081651035280652482249878204415902347144172166289192523703396002632");
        check("38192162978745386918875716193177225101344932819069282430021068056362655313179761468169539780825678053177210755685429882408274169423855381432404709790793238679496539103882365622475900037164937534403356463732623671610080123514644493871384288392474889339565516411830987322301784308467784573944319355570819737961",
              "25352190946982143794704045897134722244106908788184017546900578257527229817847113806630521171371404378409934236262808850142354478087188539237475810771667848166423716000420898005654154870056535207963944664142985711446844991434122910953507650082061556111468571926176288710921306114419224067037114938734532918531");
        check("24798989201887127840855154418531938077057854724787364244705043954803534824255707757727182751055740680744549207653528353557440861400280891608983786717941081952218310861108489291178534951409409185086774561504915772374394067939300551047947247778530400513441979462379780509713813090973986859970889277710847705109",
              "8132631661653091272741611454164637102985081175240649089930661291107605047918623070755078799927414462274818674512322109267316716715149956550210455795113206590127842659926251857211106049873203994338800723288992345791651092115793399056085567423168250640382000505459893276633163053462213342737651657788211493848");
        check("143098611503136369685915180161594265265722820859042243074449331811021751042727081718173653934915286674580009769514415311463314951365627238696760103525805553882331410895810071139331871195135166350444036826528881574318152853117378460748988305815113239193080321597716178471277306037668905677452989473169234251449",
              "70320458951177145004664540930128208120950512262911585393119726788396987591076760611654809339854949125289740903789534068188420090206616362579600812583941204569134701741049588638506883185969630393966483070918489460395462198927242720390600608626712015157354140642656820658972600817016840543221756956085122282552");
        check("11191598392415779505038676800772723392289031620935865182277840231038428210272048416458366413643782403073215108715263584831439925071710233237801908248594118800450062766738292514088638749449355105613720209579490126059491022713925948305625365716086018350884799989019587280656549580091392073988441116244164326877",
              "6319505348097590674574263256076427141502029592559291259920932151594903693711506896657640972800563937380577992941869685317512738546535697662940518530459503474497777810518573660878564076009739484302898072533488939009882806837462218561738718740416405273977259318534745942305394104798667169529974172980648467838");
        check("103817097001758930277914642902734072896504876732676771012170895271517223770886343611593812341660093980393607719673118161174021307153232547541073398627499054667062163112075272208917551804169326281217542832615777346222291210086330051397807244763716915793427556294692889651415342640742500542691587912969962220939",
              "96997077594580521649578356399870040519739314323550151846979763824660845158248809912872463532284938310318678819715801029012274410658330377899518662127873429643519160323490487636007343390097879247814416410762013097298454595929780359034785592924924147688077873579111533131791473690847013300005910102489442136542");
        check("51677487176499868591062104292321880729187592109724097942734269780118652135888475433795356918890440384688104380679468406321043557750193075285789184742277971631693020615920022738086736610890628231548883149950416439226684757657049083834656522749375361618438612572105222413753860975566865534428132144080432902296",
              "49704897842525446184899468584020085336874551553759469624713255942959927614445436984332654219174925809183115083844764289149643603173541257139763156103292809869666269856025575035604520347282888603455897295620685529513181003598509033409411254946774643617751232236817035958568594882457571726718434446813588130661");
        check("116628782128526655740770687589567165360964664587269228542569220301703780014924169870399312333382503704530178013003265400125610800744993336090945442331556758726518843054834979585897824904858179613411852983132119335048510773614452080516544856979749242096956461757836047883490616780219874098794395386460616524355",
              "12982332345148648050897735374463010127983608053015390436700639511259931040363364363182578787129718376321794309024895382799330278117892900735441143160584547348568127179185391399558858417365877352336878542186877113235844796174326600294972592186744501336090802799609522917230363393938674028929588784114918004053");
        check("34817458112214770292698055576902537923031117839556735549488594340584318294848168706713646395658271894647631619861023653049343148505284770908340399515745653857838237629453382234139934783113137547593891218851096695600786207560857855093519478076192565444836094206470190984123214510365091121900620771826996489971",
              "30675027701834726830693667225058611333209869902972732399946195335714689076141731727519363240307159041289755358539001618774451137219668601569411938453859315309443932186169734684469532564413530458643846331157559321843010014557005207422836168613212136212044908663384353089227013803065915940115953356552273157688");
        check("64555175819820328576690666132010546257523896789522548903804931030043844822211995621510454132989269116599012699155323569955084711154800690699476594001525433225455756018695217609874215987305779461351518156828263027703030677329192212834411043182745706447313117847456336615822991086842722197838504930814251097882",
              "1430767145663954541976914864041225101833702159521126480630773111834841353456994610117088787663755117209705184168990230457418967294484558535863274992857664923550229856850523792441811090787755264319231155184379718902368976436699397010273797589443505685034613578233962956061964857669375645136813790131483096587");
        check("133408590506676028956902603707012498165569418359957488833441764960527324866566196100661454253378345894059869511076535464316793395150045282952067922080762878019732839012642878145167320900037958350437144966230739886997276084290093807078687243330040482355858901134011777479023853387358954864241093311181821538888",
              "83985976304587097518513258534557631353654176203180624620586264031771092015646530754747897283322018143302697667895347458019675763787126051997258259931665499014658831805265927849324683750662390089450101548755694556569768808918065443841375598307534550195188190847126833134297503375459889205077488087202903582149");
        check("120482391764121889110044441894574085445254991692321774736327497309584835978811895580675804269584337101888569936915069846348657132540373702295709558217773109470216481074331220803746040594712492716650542739743269933916599274862064709598740175943848013184109825693782689498942104021358616726198045106960073730698",
              "74554369572238841272945852389816064021540806466342381143912712632098973012833620030862885999406541271621891744450746791960652496575931053893438060059612116321901873373949565975330388027573313328407286833766670047755592859695153964515026781102932714877553279186874195494471412449538647532230571867327835982739");
        check("99533894602257099683910974692633099668885789637856822084336938948687589540726300517522609441227225129379320800069281310234600994156757697399540030625266574432796884770315573653303771868620660944381148719237957013139361863593393525494558140460361956735410074163450260867172964422481077342353148918565504156327",
              "41809618066142500636993202634916304273890274127253897299624176270717848157349526616345511807272181376646639947592715365587246057006345906236213908589489829484904445837682742092844898829770660408484549391750383152777304440735014838105607917621080606585662299142364965149211972316447032780968679686163919053365");
        check("93144523626895660318296593828258789166017982551004142752940366215978892724376503562236732184008496825853686559121148767598038975000925050723788094652934995968866232248083308675692264674163448172554333318389809400498912118305996750854389520054193916814844353003628329765849827696296090324271814279322360799774",
              "71786545292138778204022778292150557616203726645817933663126281445639930484057326141754359283220842868393733111518388099363393972865748061488526802140260968593194903153527889495088377407444301782398990553404626279814397856317199592194655412242795068081241525827900654564061011741968220557224386586290400016389");
    }

    #[test]
    fn is_number_in_multiplicative_group_failure() {
        let check = |a: &str, b: &str| {
            let modulus = BigUint::from_str(a).unwrap();
            let number = BigUint::from_str(b).unwrap();
            assert_eq!(
                false,
                is_number_in_multiplicative_group(&modulus, &number),
                "modulus: {}, number: {}",
                modulus,
                number
            );
        };

        check("456", "123");
        check("789", "123");
        check("101112", "123");
        check("131415", "123");
    }

    #[test]
    fn get_random_positive_relatively_prime_int_success() {
        for _ in 0..100 {
            let modulus = get_random_int(1024).unwrap();
            let r = get_random_positive_relatively_prime_int(&modulus).unwrap();
            assert_eq!(true, is_number_in_multiplicative_group(&modulus, &r));
        }
    }

    #[test]
    fn get_random_positive_relatively_prime_int_failure() {
        let err = get_random_positive_relatively_prime_int(&BigUint::zero()).unwrap_err();
        assert_eq!(
            CommonError::invalid_argument(BigUint::zero(), "modulus must not be zero"),
            err
        );
    }

    #[test]
    fn get_random_generator_of_the_quadratic_residue_success() {
        for _ in 0..100 {
            let modulus = get_random_int(1024).unwrap();
            let r = get_random_generator_of_the_quadratic_residue(&modulus).unwrap();
            assert_eq!(true, r < modulus);
        }
    }

    #[test]
    fn get_random_generator_of_the_quadratic_residue_failure() {
        let err = get_random_generator_of_the_quadratic_residue(&BigUint::zero()).unwrap_err();
        assert_eq!(
            CommonError::invalid_argument(BigUint::zero(), "modulus must not be zero"),
            err
        );
    }

    #[test]
    fn get_random_quadratic_non_residue_success() {
        for _ in 0..100 {
            let mut modulus = get_random_int(1024).unwrap();
            modulus.set_bit(0, true);
            let r = get_random_quadratic_non_residue(&modulus).unwrap();
            assert_eq!(true, r < modulus);
            assert_eq!(true, r.jacobi(&modulus) == -1);
        }
    }

    #[test]
    fn get_random_quadratic_non_residue_failure() {
        let err = get_random_quadratic_non_residue(&BigUint::zero()).unwrap_err();
        assert_eq!(
            CommonError::invalid_argument(BigUint::zero(), "modulus must be odd"),
            err
        );

        let err = get_random_quadratic_non_residue(&BigUint::from(128_u8)).unwrap_err();
        assert_eq!(
            CommonError::invalid_argument(BigUint::from(128_u8), "modulus must be odd"),
            err
        );
    }
}
