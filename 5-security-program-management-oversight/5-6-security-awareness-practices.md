# 5.6 Given a scenario, implement security awareness practices
*Na podstawie podanego scenariusza, wdróż odpowiednie praktyki budowania świadomości bezpieczeństwa wśród pracowników.*

Najlepsza zapora sieciowa (ang. *firewall*) i najdroższy system wykrywania zagrożeń nie pomogą, jeśli pracownik poda swoje hasło na fałszywej stronie albo wykona *pilny przelew na prośbę prezesa*. Jak już wiemy z zagadnienia 2.2 ([Human vectors/social engineering](../2-threats-vulnerabilities-mitigations/2-2-threat-vectors-and-attack-surfaces.md#human-vectorssocial-engineering)), człowiek bywa najsłabszym ogniwem systemu bezpieczeństwa. Dobra wiadomość jest taka, że **może też być jego najmocniejszym ogniwem**, jeśli wie, na co zwracać uwagę i co robić, kiedy coś wydaje się podejrzane.

**Świadomość bezpieczeństwa** (ang. *security awareness*) to **wiedza pracowników o zagrożeniach i nawyk bezpiecznego postępowania na co dzień**. Program budowania świadomości (ang. *security awareness program*) to zaplanowany, ciągły proces, a nie jednorazowe szkolenie odhaczone przy zatrudnieniu. Na egzaminie w tym zagadnieniu dostaniemy zwykle scenariusz i będziemy musieli wskazać, jakie działanie edukacyjne lub organizacyjne najlepiej odpowiada na opisany problem.
# Phishing
Phishing jest najczęstszym sposobem atakowania pracowników (więcej o samej technice w zagadnieniu 2.2, w części [Phishing](../2-threats-vulnerabilities-mitigations/2-2-threat-vectors-and-attack-surfaces.md#phishing)), dlatego zajmuje centralne miejsce w każdym programie budowania świadomości.
## Campaigns (kampanie phishingowe)
**Kampanie phishingowe** w kontekście tego zagadnienia to **kontrolowane symulacje ataków, które organizacja przeprowadza na własnych pracownikach** (ang. *phishing simulation*). Dział bezpieczeństwa, sam lub z pomocą zewnętrznej firmy, wysyła pracownikom realistyczne, ale nieszkodliwe wiadomości phishingowe i sprawdza, kto:
- otworzył wiadomość,
- kliknął link,
- wpisał dane na fałszywej stronie,
- **zgłosił wiadomość jako podejrzaną** (to najważniejszy, pozytywny wskaźnik!).

Celem takiej kampanii **nie jest przyłapanie i ukaranie pracowników**, tylko nauka. Osoba, która dała się nabrać, powinna od razu zobaczyć krótką informację, co przeoczyła i na co zwracać uwagę następnym razem (to tzw. *nauka w momencie błędu*, ang. *teachable moment*). Organizacja, która publicznie piętnuje *klikających*, osiąga efekt odwrotny od zamierzonego: pracownicy przestają zgłaszać swoje pomyłki, a o prawdziwym incydencie dział bezpieczeństwa dowie się za późno.

Dobrze zaplanowane kampanie:
- są prowadzone regularnie, a nie raz w roku;
- mają różny poziom trudności i różne scenariusze (faktura, przesyłka, reset hasła, wiadomość od *działu IT*);
- są dopasowane do ról: księgowość dostanie inny scenariusz niż programiści;
- mierzą postęp w czasie: czy z kampanii na kampanię spada odsetek kliknięć i rośnie odsetek zgłoszeń.
## Recognizing a phishing attempt (rozpoznawanie prób phishingu)
**Rozpoznawanie prób phishingu** to umiejętność, którą pracownicy powinni ćwiczyć najczęściej. Typowe sygnały ostrzegawcze:
- **Presja czasu i emocje** (ang. *urgency*) – *pilne*, *ostatnie wezwanie*, *konto zostanie zablokowane w ciągu 24 godzin*. Pośpiech ma odebrać nam chwilę na zastanowienie.
- **Nietypowa prośba** – podanie hasła, kodu z SMS-a, zmiana numeru konta kontrahenta, zakup kart podarunkowych, instalacja programu do zdalnej pomocy (ang. *remote access tool*).
- **Nadawca, który się nie zgadza** – adres e-mail z literówką, domena podobna do prawdziwej (ang. *typosquatting*), wyświetlana nazwa nadawcy niezgodna z adresem.
- **Linki prowadzące gdzie indziej, niż sugeruje treść** – po najechaniu kursorem (bez klikania!) widać prawdziwy adres docelowy.
- **Nieoczekiwane załączniki** – szczególnie archiwa, pliki wymagające *włączenia makr* albo pliki o podwójnym rozszerzeniu.
- **Ogólnikowe powitanie i błędy językowe** – choć uwaga: dzięki narzędziom AI wiadomości phishingowe są dziś coraz częściej napisane bezbłędną polszczyzną, więc brak błędów niczego nie dowodzi.

Najważniejsza zasada, którą warto przekazać pracownikom: **jeśli wiadomość prosi o coś nietypowego, zweryfikuj ją innym kanałem** (ang. *out-of-band verification*). Zadzwoń do nadawcy na znany ci numer (nie ten z wiadomości), wpisz adres banku ręcznie w przeglądarce, zapytaj przełożonego osobiście. CERT Polska (CERT, ang. *Computer Emergency Response Team*, zespół reagowania na incydenty komputerowe) przygotował praktyczny poradnik [Rozpoznanie phishingu](https://wiedza.cert.pl/bezpieczenstwo-osobiste/rozpoznanie-phishingu/).
## Responding to reported suspicious messages (reagowanie na zgłoszone podejrzane wiadomości)
**Reagowanie na zgłoszone podejrzane wiadomości.** Program budowania świadomości działa tylko wtedy, gdy pracownicy **wiedzą, jak zgłosić podejrzaną wiadomość, i chętnie to robią**. Dlatego organizacja powinna:
- zapewnić **jeden, prosty sposób zgłaszania**, np. przycisk *Zgłoś phishing* w kliencie poczty albo dedykowany adres e-mail;
- **dziękować za każde zgłoszenie**, także za fałszywy alarm (ang. *false positive*) – lepiej sprawdzić dziesięć niegroźnych wiadomości niż przegapić jedną prawdziwą;
- **szybko odpowiadać** zgłaszającemu, czy wiadomość była groźna i co ma zrobić dalej.

Po stronie zespołu bezpieczeństwa każde zgłoszenie przechodzi analizę: czy wiadomość jest złośliwa, kto jeszcze ją dostał i czy ktoś zdążył kliknąć. Jeśli tak, uruchamia się procedura reagowania na incydent (ang. *incident response*, więcej w zagadnieniu 4.8): usunięcie wiadomości ze wszystkich skrzynek, zablokowanie nadawcy i złośliwych adresów, a w razie podania hasła – jego natychmiastowa zmiana i sprawdzenie, czy ktoś nie zalogował się na konto ofiary.

Warto też wiedzieć, jak zgłaszać podejrzane wiadomości poza firmą. W Polsce podejrzanego SMS-a można bezpłatnie **przesłać na numer 8080**, skąd trafia do analizy w CERT Polska ([gov.pl](https://www.gov.pl/web/baza-wiedzy/coraz-wiecej-prob-wyludzenia-przez-tzw-falszywe-sms-y-zachowaj-czujnosc)), a fałszywe strony i inne incydenty można zgłaszać przez formularz [incydent.cert.pl](https://incydent.cert.pl/). Strony uznane za niebezpieczne trafiają na listę ostrzeżeń CERT Polska, dzięki której operatorzy mogą blokować do nich dostęp.
# Anomalous behavior recognition (rozpoznawanie nietypowych zachowań)
**Rozpoznawanie nietypowych zachowań.** Pracownicy powinni umieć zauważyć, że **coś odbiega od normy**, zarówno w zachowaniu współpracowników, jak i we własnych działaniach czy w działaniu systemów. Nie chodzi o to, żeby wszyscy się nawzajem pilnowali, ale żeby wiedzieli, co zgłaszać i komu. Egzamin wyróżnia trzy rodzaje takich zachowań.
## Risky (zachowania ryzykowne)
**Zachowania ryzykowne**, czyli działania podejmowane świadomie, ale **wbrew zasadom bezpieczeństwa**, zazwyczaj dla wygody. Przykłady:
- zapisywanie haseł na karteczce przyklejonej do monitora;
- przesyłanie firmowych dokumentów na prywatną skrzynkę, żeby popracować w domu;
- wyłączanie oprogramowania antywirusowego, *bo spowalnia komputer*;
- instalowanie nieautoryzowanych aplikacji (patrz [Shadow IT](../2-threats-vulnerabilities-mitigations/2-1-threat-actors-and-motivations.md#shadow-it)).
## Unexpected (zachowania nieoczekiwane)
**Zachowania nieoczekiwane**, czyli takie, które **nie pasują do zwykłego wzorca pracy danej osoby lub systemu**. Mogą świadczyć o przejęciu konta (ang. *account takeover*) albo o działaniach nieuczciwego pracownika (ang. *malicious insider*). Przykłady:
- pracownik działu kadr nagle pobiera duże ilości danych z systemów finansowych;
- logowanie na konto w środku nocy albo z innego kraju;
- prośba o dostęp do zasobów, które nie są potrzebne na danym stanowisku;
- współpracownik, który bez wyraźnego powodu interesuje się projektami innych zespołów.

Część takich anomalii wykrywają automatycznie systemy monitorujące (np. analityka zachowań użytkowników, ang. *User and Entity Behavior Analytics*, UEBA), ale człowiek, który zna kontekst, często zauważy je szybciej.
## Unintentional (zachowania nieumyślne)
**Zachowania nieumyślne**, czyli **błędy popełnione bez złej woli**:
- wysłanie e-maila z poufnymi danymi do niewłaściwego odbiorcy (np. przez autouzupełnianie adresu);
- zgubienie służbowego laptopa lub telefonu;
- udostępnienie pliku w chmurze *każdemu, kto ma link*, zamiast konkretnym osobom;
- kliknięcie w link phishingowy.

Kluczowe jest to, żeby **pracownik, który popełnił błąd, od razu go zgłosił**. Każda minuta ma znaczenie: zgubiony laptop można zdalnie zablokować, a skradzione hasło zmienić, zanim ktoś je wykorzysta. Dlatego kultura organizacji, w której za zgłoszenie własnego błędu nie grozi kara (ang. *no-blame culture*), jest jednym z najważniejszych elementów bezpieczeństwa.
# User guidance and training (wytyczne i szkolenia dla użytkowników)
**Wytyczne i szkolenia dla użytkowników.** Egzamin wymienia konkretne obszary, które powinien obejmować program szkoleń. Szkolenie warto dopasować do odbiorców: inaczej uczymy nowego pracownika, inaczej administratora systemów, a jeszcze inaczej zarząd, który jest ulubionym celem ataków typu *whaling*.
## Policy/handbooks (polityki i podręczniki)
**Polityki i podręczniki.** Pracownicy muszą wiedzieć, **jakie zasady obowiązują w organizacji**: polityka akceptowalnego użytkowania (ang. *Acceptable Use Policy*, AUP), polityka haseł, zasady klasyfikacji danych (ang. *data classification*), procedura zgłaszania incydentów. Dobre praktyki:
- dokumenty są napisane prostym językiem, a nie wyłącznie prawniczym;
- nowy pracownik zapoznaje się z nimi przy zatrudnieniu (ang. *onboarding*) i potwierdza to podpisem;
- ważne zasady są dostępne w jednym, łatwym do znalezienia miejscu (np. w intranecie) i regularnie aktualizowane.
## Situational awareness (świadomość sytuacyjna)
**Świadomość sytuacyjna**, czyli **uważność na otoczenie i nietypowe sytuacje w codziennej pracy**. Przykłady:
- nieznana osoba próbuje wejść do biura *na doczepkę* za pracownikiem (ang. *tailgating*);
- ktoś podgląda ekran laptopa w pociągu (ang. *shoulder surfing*);
- na biurku w sali konferencyjnej leżą wydrukowane dokumenty po spotkaniu (tu pomaga zasada czystego biurka, ang. *clean desk policy*);
- *serwisant*, którego nikt nie zamawiał, prosi o dostęp do serwerowni.

Świadomość sytuacyjna to zdolność zauważenia, że coś jest nie tak, **zanim** dojdzie do incydentu.
## Insider threat (zagrożenie wewnętrzne)
Szkolenie z **zagrożeń wewnętrznych** (pojęcie opisane w zagadnieniu 2.1, w części [Insider threat](../2-threats-vulnerabilities-mitigations/2-1-threat-actors-and-motivations.md#insider-threat)) ma uczyć pracowników, **jakie sygnały mogą świadczyć o zagrożeniu ze strony współpracownika i jak je zgłosić**, a także uświadamiać, że sami mogą stać się celem werbunku albo manipulacji ze strony przestępców. Ważne jest, żeby takie szkolenie nie budowało atmosfery wzajemnej podejrzliwości, tylko zaufania do procedur: zgłoszenie trafia do odpowiednich osób, które sprawdzą sprawę dyskretnie i rzetelnie.
## Password management (zarządzanie hasłami)
**Zarządzanie hasłami.** Szkolenie powinno obejmować:
- tworzenie długich, unikalnych haseł (np. w formie **hasła wielowyrazowego**, ang. *passphrase*), **innych dla każdego serwisu**;
- korzystanie z **menedżera haseł** (ang. *password manager*), który generuje i pamięta hasła za nas;
- włączanie **uwierzytelniania wieloskładnikowego** (ang. *Multi-Factor Authentication*, MFA) wszędzie, gdzie to możliwe;
- zasadę, że **hasła nie podajemy nikomu**, także osobie podającej się za dział IT.

Warto wyjaśnić, *dlaczego* te zasady są ważne. Jeśli to samo hasło jest używane w wielu miejscach, wyciek z jednego serwisu (np. sklepu internetowego) pozwala przestępcom zalogować się do pozostałych (ang. *credential stuffing*).
## Removable media and cables (nośniki wymienne i kable)
**Nośniki wymienne i kable.** Pracownicy powinni wiedzieć, że **pendrive znaleziony na parkingu albo kabel USB *gratis* z konferencji to potencjalne narzędzie ataku** (szczegóły w zagadnieniu 2.2, w części [Removable device](../2-threats-vulnerabilities-mitigations/2-2-threat-vectors-and-attack-surfaces.md#removable-device)). Zasady do przekazania na szkoleniu:
- nie podłączamy nośników i urządzeń nieznanego pochodzenia; znaleziony pendrive oddajemy do działu IT;
- do przenoszenia danych używamy wyłącznie służbowych, szyfrowanych nośników, jeśli w ogóle są dozwolone;
- telefonu nie ładujemy z nieznanych portów USB (np. na lotnisku); bezpieczniej użyć własnej ładowarki podłączonej do gniazdka (zagrożenie to *juice jacking*).
## Social engineering (socjotechnika)
**Socjotechnika** (inżynieria społeczna). Szkolenie powinno pokazywać **typowe techniki manipulacji**: pretekst (ang. *pretexting*), podszywanie się pod przełożonych lub instytucje (ang. *impersonation*), presję czasu, granie na emocjach i chęci pomocy. Najlepiej działają przykłady z życia i krótkie scenki: telefon od *działu IT* z prośbą o kod z SMS-a, e-mail od *prezesa* z prośbą o pilny przelew, wiadomość na komunikatorze od *znajomego*, który potrzebuje kodu BLIK. Pracownik, który raz *przeżył* taki scenariusz na szkoleniu, łatwiej rozpozna go w rzeczywistości.
## Operational security (bezpieczeństwo operacyjne)
**Bezpieczeństwo operacyjne** (ang. *operational security*, OPSEC) to **ochrona informacji, które z pozoru wydają się nieistotne, ale mogą pomóc atakującemu**. Zdjęcie z biura w mediach społecznościowych z widocznym hasłem do Wi-Fi na tablicy, informacja o wyjeździe służbowym prezesa, struktura zespołu opisana na profilu zawodowym, plotka o nowym kontrakcie przy kawie w kawiarni. Każdy taki element atakujący może wykorzystać do przygotowania przekonującego pretekstu albo ataku spersonalizowanego (ang. *spear phishing*). Szkolenie z OPSEC uczy, **co i gdzie można bezpiecznie publikować i mówić o pracy**.
## Hybrid/remote work environments (praca hybrydowa i zdalna)
**Praca hybrydowa i zdalna** przenosi część biura do domów, kawiarni i pociągów, a razem z nim nowe ryzyka:
- domowa sieć Wi-Fi i router, którymi nie zarządza dział IT (często z domyślnym hasłem, ang. *default credentials*);
- publiczne sieci Wi-Fi;
- domownicy korzystający z tego samego komputera albo widzący ekran podczas spotkań;
- rozmowy służbowe prowadzone w miejscach publicznych.

Zasady do przekazania: łączymy się z siecią firmową przez VPN (ang. *Virtual Private Network*), nie zostawiamy odblokowanego komputera, nie używamy sprzętu służbowego do celów prywatnych (i odwrotnie), dbamy o prywatność ekranu i rozmów oraz aktualizujemy domowy router.
# Reporting and monitoring (raportowanie i monitorowanie)
**Raportowanie i monitorowanie** pozwala sprawdzić, **czy program budowania świadomości w ogóle działa**. Bez pomiarów nie wiemy, czy szkolenia cokolwiek zmieniają. Typowe miary (ang. *metrics*) to:
- odsetek pracowników, którzy ukończyli szkolenia,
- odsetek kliknięć i podanych haseł w kampaniach phishingowych,
- odsetek i czas zgłoszeń podejrzanych wiadomości,
- liczba incydentów spowodowanych błędem człowieka.
## Initial (raportowanie początkowe)
**Raportowanie początkowe** (ang. *initial*) ustala **punkt odniesienia** (ang. *baseline*), czyli stan wiedzy i zachowań pracowników **przed** rozpoczęciem programu lub tuż po zatrudnieniu, np. wynik pierwszej kampanii phishingowej czy testu wiedzy. Bez punktu odniesienia nie da się stwierdzić, czy późniejsze działania przyniosły poprawę.
## Recurring (raportowanie cykliczne)
**Raportowanie cykliczne** (ang. *recurring*) to **regularne, powtarzane sprawdzanie** tych samych wskaźników, np. co kwartał. Pozwala śledzić postęp w czasie, wychwycić działy, które potrzebują dodatkowego wsparcia, i dostosować program do nowych zagrożeń. Wyniki są raportowane kierownictwu, żeby uzasadnić inwestycję w program i podejmować decyzje na podstawie danych.
# Development (opracowanie programu)
**Opracowanie programu** (ang. *development*), czyli przygotowanie programu budowania świadomości, zanim zostanie wdrożony. Na tym etapie organizacja:
- określa **cele** programu i grupy odbiorców (cała firma, działy szczególnie narażone, kadra zarządzająca);
- wybiera **tematy** na podstawie realnych zagrożeń dla organizacji (np. analizy dotychczasowych incydentów);
- dobiera **formy**: szkolenia e-learningowe, warsztaty, krótkie filmy, plakaty, newslettery, symulacje phishingu;
- ustala **harmonogram** oraz sposób mierzenia efektów (patrz [Reporting and monitoring](#reporting-and-monitoring-raportowanie-i-monitorowanie)).

Dobry program jest **dopasowany do organizacji**: inaczej będzie wyglądał w szpitalu, inaczej w firmie produkcyjnej, a jeszcze inaczej w software housie.
# Execution (realizacja programu)
**Realizacja programu** (ang. *execution*), czyli jego wdrożenie i prowadzenie w praktyce. Ważne zasady:
- **ciągłość** – krótkie, regularne działania działają lepiej niż jedno długie szkolenie raz w roku;
- **zaangażowanie kierownictwa** (ang. *leadership buy-in*) – jeśli zarząd sam przestrzega zasad i bierze udział w szkoleniach, pracownicy traktują je poważniej;
- **pozytywny przekaz** – nagradzamy zgłoszenia, zamiast karać za błędy;
- **aktualność** – treści są odświeżane, gdy pojawiają się nowe techniki ataków (np. oszustwa wykorzystujące podrobiony głos czy wideo, ang. *deepfake*);
- **informacja zwrotna** – wyniki z [Reporting and monitoring](#reporting-and-monitoring-raportowanie-i-monitorowanie) wracają do etapu [Development](#development-opracowanie-programu) i program jest na ich podstawie poprawiany.

Program budowania świadomości to więc **cykl**: opracowanie, realizacja, pomiar i poprawa, powtarzany bez końca, bo zagrożenia też ciągle się zmieniają.
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
- [CERT Polska: Rozpoznanie phishingu](https://wiedza.cert.pl/bezpieczenstwo-osobiste/rozpoznanie-phishingu/)
- [gov.pl: Coraz więcej prób wyłudzenia przez tzw. fałszywe SMS-y – zachowaj czujność](https://www.gov.pl/web/baza-wiedzy/coraz-wiecej-prob-wyludzenia-przez-tzw-falszywe-sms-y-zachowaj-czujnosc)
- [NIST SP 800-63B: Digital Identity Guidelines – Authentication and Lifecycle Management](https://csrc.nist.gov/pubs/sp/800/63/B/4/final)
