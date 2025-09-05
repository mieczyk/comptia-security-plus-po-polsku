# 1.2 Summarize fundamental security concepts
Streść fundamentalne zagadnienia związane z bezpieczeństwem.
# Confidentiality, Integrity, and Availability (CIA)
**Triada CIA**, często przedstawiana graficznie w formie trójkąta, opisuje **fundamentalne cele bezpieczeństwa IT**. Są to:
- **Poufność (ang. *confidentiality*)** - ochrona przed nieautoryzowanym dostępem.
- **Nienaruszalność (ang. *integrity*)** - ochrona przed niepożądaną modyfikacją danych.
- **Dostępność (ang. *availability*)** - zapewnienie, że autoryzowani użytkownicy mają dostęp do danych, kiedy tylko tego potrzebują.

Zbieżność z akronimem amerykańskiej Centralnej Agencji Wywiadowczej (CIA = *Central Intelligence Agency*) jest przypadkowa, ale to skojarzenie pomaga zachować skrót na dłużej w pamięci.

Czasami można się jeszcze spotkać z terminem **triady DAD** (*Disclosure, Alteration, Denial*), która przedstawia **trzy główne zagrożenia dla bezpieczeństwa IT** i stanowi zupełne przeciwieństwo triady CIA:
- Ujawnienie poufnych informacji nieupoważnionym osobom (ang. *disclosure*), czyli naruszenie zasady poufności.
- Niepożądana i nieautoryzowana zmiana danych (ang. *alteration*), czyli naruszenie zasady nienaruszalności.
- Odmowa dostępu do danych (ang. *denial*), czyli naruszenie zasady dostępności.

Zarówno triada CIA, jak i DAD są przydatnym punktem wyjściowym w procesie planowania i analizy ryzyka, podczas którego szacuje się prawdopodobieństwo wystąpienia ataków bądź zdarzeń losowych oraz ocenia się ich potencjalne skutki. Później, na podstawie wniosków, wdraża się stosowne środki bezpieczeństwa (ang. *security controls*). Prawdziwym wyzwaniem dla zespołów dbających o bezpieczeństwo IT jest zapewnienie odpowiedniego poziomu dostępności do danych, przy jednoczesnym zachowaniu ich poufności.

***Non-repudiation*** (niezaprzeczalność) nie wchodzi w skład triady CIA, ale jest również ważnym filarem bezpieczeństwa IT. Zapewnia, że osoba, która podjęła jakieś działanie (np. wysłała wiadomość) nie może się później tego wyprzeć. Dobrym przykładem środka dbającego o ten aspekt są podpisy cyfrowe.

W niektórych opracowaniach można spotkać z dodatkowym celem bezpieczeństwa IT, którym jest **odpowiedzialność** (ang. *accountability*). Chodzi tutaj o zbieranie informacji o aktywności użytkowników, żeby zawsze dało się wskazać osobę odpowiedzialną za dany incydent.
## Confidentiality
Jednym z podstawowych celów bezpieczeństwa IT jest **ochrona poufnych informacji przed dostępem osób, które nie są do nich upoważnione**. Naruszenie poufności danych może być **intencjonalne** (np. atakujący uzyskał nieautoryzowany dostęp do bazy danych) bądź **niezamierzone** (np. nastąpił wyciek w wyniku błędu pracownika organizacji).

Wybrane [środki bezpieczeństwa](https://vilya.pl/sy0-701-security-controls-pl/) (ang. *security controls*), które pomagają osiągnąć cel poufności:
- **Szyfrowanie danych** (ang. *data encryption*), zarówno tych w spoczynku (ang. *at-rest*), przechowywanych na nośnikach danych, jak i przesyłanych przez sieć (ang. *in-transit*). Dzięki temu, jedynie osoba posiadająca odpowiedni klucz będzie w stanie odczytać informacje w oryginalnej formie.
- **Kontrola dostępu do danych** (ang. *access control*) i udzielanie go jedynie uprawnionym użytkownikom bądź urządzeniom. Można w tym celu wykorzystać m.in. firewalle, które filtrują ruch sieciowy, czy też listy kontroli dostępu ACL (*Access-Control List*). Najprostszym przykładem wykorzystania ACL jest konfigurowanie w systemie operacyjnym, kto ma dostęp do wybranych plików i katalogów.
- Sprawdzone **mechanizmy [uwierzytelniające](https://vilya.pl/sy0-601-metody-lamania-hasel/#storing-passwords)** (ang. *authentication*), w tym **uwierzytelniania wieloskładnikowe** (MFA = *Multi-Factor Authentication*).
- Czasami można spotkać się z wykorzystaniem [**steganografii**](https://pl.wikipedia.org/wiki/Steganografia), czyli mechanizmów, których zadaniem jest ukrycie faktu jakiejkolwiek komunikacji (w odróżnieniu od szyfrowania, gdzie wymiana informacji jest jawna). Teoretycznie, ukrycie samej komunikacji może zwiększyć poziom poufności, jednakże bez dodatkowego zaszyfrowania ukrytej wiadomości, nie jest to środek wystarczający.
## Integrity
Drugim głównym celem obszaru *IT security* jest **spójność/nienaruszalność danych**, czyli pewność, że **oryginalne danie nie zostały w żaden sposób zmodyfikowane, w wyniku niepożądanych działań**. Przykładowo, jeśli nastąpiła transmisja danych między użytkownikami, chcemy mieć pewność, że odbiorca otrzymał identyczną wiadomość, jaka została wysłana przez nadawcę i nikt przy niej *nie majstrował* w międzyczasie.

Nawet jeśli dane zostały w jakiś sposób naruszone, powinniśmy móc to jak najszybciej wykryć. Dane mogą zostać zmodyfikowane przez **atakujących**, ale naruszenie spójności może też nastąpić w efekcie **nieoczekiwanego zdarzenia** (np. problemy z siecią mogą skutkować *gubieniem* [pakietów](https://pl.wikipedia.org/wiki/Pakiet_telekomunikacyjny)).

Przykładem intencjonalnego naruszenia spójności danych jest podmiana treści strony firmowej (ang. *website defacement*). Ciekawostka: w 1996 roku, w wyniku ataku, [zmieniona została witryna internetowa agencji wywiadowczej CIA](https://gizmodo.com/sick-burns-in-history-hackers-change-cia-to-central-st-1692168198).

Środki bezpieczeństwa, które pomagają zweryfikować integralność danych:
- **Hashing** to metoda polegająca na wyliczeniu tzw. [skrótu](https://vilya.pl/sy0-601-metody-lamania-hasel/#hash) (*hash*), czyli nieuporządkowanego ciągu znaków o stałej długości, na podstawie danych wejściowych. Hash charakteryzuje się tym, że powinien być niepowtarzalny (przynajmniej w teorii) dla różnych danych wejściowych - nawet niewielka zmiana w oryginalnym tekście (np. dostawienie przecinka) powinna skutkować wygenerowaniem zupełnie innego skrótu. Jeśli odbiorca otrzyma informacje wraz z skrótem i będzie w stanie uzyskać identyczny hash, za pomocą tej samej funkcji [hashującej](https://vilya.pl/sy0-601-metody-lamania-hasel/#hashing-function), to ma pewność, że wiadomość nie została *po drodze* zmieniona.
- **Podpis elektroniczny** (ang. *digital signature*) z wykorzystaniem szyfrowania asymetrycznego (z użyciem klucza prywatnego i publicznego). W skrócie: na podstawie przesyłanych danych liczony jest hash, który zostaje zaszyfrowany kluczem prywatnym nadawcy i dołączony do wiadomości (hash, nie klucz). Odbiorca może później odszyfrować otrzymany hash za pomocą klucza publicznego nadawcy. Dzięki temu odbiorca ma dodatkową pewność, że wiadomość nie tylko nie została naruszona, ale też została wysłana przez właściciela klucza.
- **Certyfikat elektroniczny** (ang. *digital certificate*) jest to (w dużym uproszczeniu) dodatkowe poświadczenie, które potwierdza, że klucze użyte do stworzenia i weryfikacji podpisu elektronicznego, rzeczywiście należą do spodziewanego nadawcy.
## Availability
Trzecim filarem bezpieczeństwa IT jest zapewnienie, że **dane są dostępne zweryfikowanym użytkownikom zawsze, kiedy tego potrzebują**.

Zdarzenia naruszające regułę dostępności mogą być **zamierzone** (np. ataki typu *odmowa usługi* DoS/DDoS) lub **przypadkowe** (np. awaria serwera; katastrofa naturalna w regionie, gdzie znajduje się nasze centrum danych).

Systemy należy projektować i budować w taki sposób, żeby charakteryzowały się wysoką dostępnością (ang. *high availability*) i były odporne na awarie. Środki, które mogą w tym pomóc:
- Stosowanie mechanizmów ***fault tolerance*** (w dosłownym tłumaczeniu: tolerowanie awarii), które zapewniają ciągłość działania systemu, pomimo niesprawności jego określonych elementów. Na przykład: łączenie serwerów w [klastry](https://pl.wikipedia.org/wiki/Klaster_komputerowy); stosowanie macierzy [RAID](https://centrumodzyskiwaniadanych.pl/blog/204-macierze-raid-informacje).
- Systematyczne **tworzenie kopii zapasowych** (ang. *backup*), na podstawie których jesteśmy w stanie szybko odtworzyć stan systemu przed incydentem.
- **Monitorowanie** działania systemu (sieci, serwerów, aplikacji) z ustawionymi powiadomieniami (ang. *alerts*) o ewentualnych anomaliach.
- Regularne **aktualizowanie oprogramowania** celem utrzymania systemów w możliwie *świeżym* stanie (ang. *up-to-date*). Dzięki temu minimalizujemy szansę wystąpienia usterek przez błędy w oprogramowaniu.
- *Business Continuity Plan* (BCP) - dokument określający środki i działania, jakie należy podjąć, żeby zapewnić ciągłość działania organizacji.
# Non-repudiation
Zasada **niezaprzeczalności** (ang. *non-repudiation*), oprócz bycia jednym z fundamentalnych zasad bezpieczeństwa IT, jest również istotnym elementem kryptografii. **Zapewnia, że otrzymana wiadomość, w niezmienionej formie, została wysłana przez domniemanego nadawcę, który teraz nie może tego faktu się wyprzeć**.

Aby osiągnąć *niezaprzeczalność* w cyfrowym świecie, stosuje się m.in. **podpis elektroniczny** (ang. *digital signature*), który można traktować jako wirtualny odcisk palca (ang. *fingerprint*). Podpis cyfrowy jest w pewnym stopniu odpowiednikiem odręcznego podpisu na fizycznym dokumencie.

Mechanizmy kryptograficzne, wykorzystywane w podpisach elektronicznych, są w stanie dostarczyć nam **dowód niezmienności** (ang. *proof of integrity*) oraz **dowód pochodzenia** (ang. *proof of origin*), co przekłada się na zapewnienie wysokiego stopnia autentyczności.

***Proof of integrity*** - dowód niezmienności, dzięki któremu jesteśmy w stanie zweryfikować, że otrzymane informacje są dokładnie takie same, jak te wysłane przez nadawcę. Dane są spójne i nic nie zostało w nich zmienione od chwili nadania, aż do momentu odczytania.
- Osiągalny dzięki mechanizmowi [hashowania](https://vilya.pl/sy0-601-metody-lamania-hasel/#hash-calculation), czyli obliczania [skrótu](https://vilya.pl/sy0-601-metody-lamania-hasel/#hash-definicja) (ang. *hash*), reprezentującego dane w postaci krótkiego ciągu znaków o stałej długości. Hash, dzięki swoim właściwościom, pomaga stwierdzić, czy treść wiadomości nie uległa zmianie.
- Jeśli stwierdzimy, że hash dołączony do otrzymanych danych różni się od tego, który sami obliczyliśmy (zakładając, że używamy dokładnie tej samej funkcji hashującej), powinno to wzbudzić nasze podejrzenia. Oryginalna wiadomość mogła zostać uszkodzona lub celowo zmieniona.
- Należy pamiętać, ze sam skrót nie daje możliwości weryfikacji źródła wiadomości.

***Proof of origin*** - dowód pochodzenia daje możliwość weryfikacji, kto wysłał nam wiadomość i stanowi najważniejszy element zasady niezaprzeczalności. Do utworzenia podpisu cyfrowego przez nadawcę wykorzystywany jest jej/jego **klucz prywatny** (ang. *private key*), a do weryfikacji tegoż podpisu **klucz publiczny** (ang. *public key*).

Uwaga! Należy pamiętać, że przedstawiona zasada niezaprzeczalności opiera się na założeniu, że klucz prywatny jest w posiadaniu domniemanego nadawcy i jest dobrze chroniony.
# Authentication, Authorization, and Accounting (AAA)
Framework (czyli ramy, które definiują strukturę oraz ogólny mechanizm działania) określany mianem **AAA (*Authentication, Authorization, Accounting*) jest istotnym elementem bezpieczeństwa sieciowego, a jego zadaniem jest kontrola i rejestrowanie dostępu do chronionych zasobów**. Mówiąc krótko: **determinuje, kto i do jakich elementów systemu ma dostęp, a także śledzi poczynania zalogowanych użytkowników.**

Jak wygląda bardzo ogólny proces nadawania dostępu do wybranych zasobów, będący częścią frameworka AAA:
1. Pierwszym krokiem jest **identyfikacja (ang. *identification*)**. Jeśli chcemy uzyskać dostęp do systemu, **musimy się przedstawić jako jego uprawniony użytkownik**. W najczęstszym przypadku polega to na podaniu danych uwierzytelniających w postaci unikatowej nazwy użytkownika i hasła, ale mogą to być również inne czynniki uwierzytelniające, takie jak odcisk palca czy sprzętowy klucz USB.
2. Kiedy już się *kulturalnie przedstawiliśmy*, przechodzimy do etapu **uwierzytelnienia (ang. *authentication*). Teraz system weryfikuje podane przez nas informacje uwierzytelniające i próbuje potwierdzić na podstawie danych w swojej bazie, że na pewno jesteśmy tymi, za kogo się podajemy**. Jeśli wszystko się zgadza, zostajemy uwierzytelnieni i otrzymujemy dostęp do systemu.
3. Po potwierdzeniu naszej tożsamości, czas na **autoryzację (ang. *authorization*)**. To, że umożliwiono nam wejście do systemu, nie oznacza automatycznie, że mamy dostęp do wszystkich jego zasobów. **Proces autoryzacji polega na przyznawaniu użytkownikowi dostępu do określonych zasobów, w zależności od jego uprawnień**. Na przykład, kiedy logujemy się do naszej bankowości elektronicznej, mamy dostęp jedynie do naszego konta, a nie do kont innych klientów. Pracownicy banku również są użytkownikami systemu bankowego i mogą mieć szerszy zakres uprawnień (np. podgląd kont swoich klientów, ale bez możliwości wykonywania na nich operacji).
4. Trzecim filarem frameworka AAA jest **śledzenie i rejestrowanie działań użytkowników w systemie, czyli tzw. *accounting*** (można to przetłumaczyć dosłownie jako *rozliczanie* bądź *księgowanie*). Monitorowanie aktywności użytkowników w systemie (czas logowania/wylogowania; operacje wykonywane na określonych zasobach itp.) jest bardzo istotnym elementem dbania o bezpieczeństwo. Dzięki temu administratorzy systemu mogą z powodzeniem przeprowadzać audyty bezpieczeństwa, wykrywać anomalie, a także analizować skutki oraz przyczyny ewentualnych incydentów.

Pamiętajmy, że przedstawiony wyżej ogólny opis frameworka AAA jest jedynie abstrakcyjnym konceptem, którego implementacja może mocno różnić się od strony technicznej, w zależności od potrzeb. Inaczej wygląda mechanizm pilnowania dostępu do pojedynczego urządzenia (np. przez protokół SSH), gdzie cały proces AAA może odbywać się pod kontrolą systemu operacyjnego tego urządzenia, a jeszcze inaczej, gdy użytkownik próbuję uzyskać dostęp do całej sieci (np. przez VPN), w której funkcjonuje scentralizowany serwer AAA. 

Ogólny proces kontroli dostępu do chronionych zasobów, z wykorzystaniem scentralizowanego serwera AAA (na przykładzie protokołu RADIUS), mógłby wyglądać następująco: 

![AAA server access](https://github.com/mieczyk/comptia-security-plus-po-polsku/blob/main/media/1-2-AAA-server-access.png)

Przykłady popularnych protokołów AAA:
- **RADIUS** (*Remote Access Dial-In User Service*) - protokół będący otwartym standardem, realizujący założenia frameworka AAA, który powstał w 1991 roku i jest do dzisiaj wykorzystywany (**głównie w sieciach bezprzewodowych**). **Uwierzytelnienie oraz autoryzacja są realizowane w ramach pojedynczego kroku**, podczas gdy śledzenie aktywności odbywa się w osobnym procesie. Starsze implementacje wykorzystywały porty UDP o numerach 1645 (*authentication, authorization*) oraz 1646 (*accounting*), natomiast nowsze wersje używają w tym samym celu portów **UDP** **1812** (uwierzytelnienie i autoryzacja) oraz **1813** (rejestrowanie poczynań). Podczas komunikacji sieciowej **jedynie hasła są zaszyfrowane** - pozostałe informacje są przesyłane w formie jawnej.
- **TACACS+** (*Terminal Access Controller Access-Control System*) to protokół opracowany przez firmę Cisco (aktualnie wspierany również przez innych dostawców) i jest wykorzystywany **głównie do zarządzania urządzeniami sieciowymi**. W odróżnieniu od RADIUS-a, **szyfrowana jest cała zwartość pakietów** podczas komunikacji sieciowej, a nie tylko hasła. Poza tym, TACACS+ operuje na porcie **49 TCP** oraz **rozdziela proces uwierzytelnienia od autoryzacji**, co umożliwia bardziej szczegółową kontrolę.
## Authenticating people
Uwierzytelnianie osób (ludzi) opiera się na trochę innych zasadach niż uwierzytelnianie systemów, gdzie polegamy głównie na certyfikatach i podpisach cyfrowych.

**Mechanizmy odpowiedzialne za uwierzytelnienie człowieka muszą odznaczać się pewną dozą zaufania**, ponieważ tak naprawdę nie są w stanie określić, podczas weryfikacji, czy wybrane atrybuty okazywane w świecie cyfrowym mają odzwierciedlenie w świecie rzeczywistym (np. czy prawidłowe hasło rzeczywiście podał uprawniony użytkownik).

**Dodatkowym wyzwaniem jest dobranie takich czynników uwierzytelniających, które nie będą stanowić poważnego naruszenia prywatności**. Cała sztuka polega na oparciu mechanizmów uwierzytelniających na możliwie najmniejszej liczbie atrybutów, które są w stanie jednoznacznie potwierdzić, że ich posiadacz jest rzeczywiście tym, za kogo się podaje.

Szczegółowość weryfikacji określonych atrybutów powinna być też adekwatna do wymagań danego systemu. Na przykład, systemy bankowe powinny być bardziej wnikliwe w procesie uwierzytelniania, niż internetowe fora wędkarskie (nawet jeśli ktoś jest fanatykiem wędkarstwa).

Popularne czynniki (atrybuty) uwierzytelniające, które mogą charakteryzować daną osobę i stanowić podstawę do jej uwierzytelnienia:
- **Coś, co wiesz (ang. *something you know*)** - najpopularniejsza metoda uwierzytelniająca, opierająca się na tym, że dany użytkownik wie coś, czego nie wiedzą inni. Przeważnie jest to hasło, kod PIN, odpowiedzi na pytania weryfikujące itd.
- **Coś, co posiadasz (ang. *something you have*)** - metoda powszechnie stosowana jako dodatkowy czynnik uwierzytelniający (MFA, 2FA), bazująca na tym, że dany użytkownik jest w posiadaniu czegoś, czego nie mają inni. Może to być telefon z aplikacją mobilną, generującą jednorazowe kody dostępu, bądź też klucz sprzętowy.
- **To, kim jesteś (ang. *something you are*)** - metoda weryfikujące unikatowe, fizyczne cechy użytkownika (biometria). Polega na sprawdzaniu linii papilarnych, rozpoznawaniu twarzy i/lub głosu, czy też skanowaniu siatkówki oka. Dobrze zaimplementowana biometria jest jedną z najskuteczniejszych metod uwierzytelniających jeśli chodzi o ludzi, jednak może powodować inne problemy: konieczność stosowania specjalistycznego sprzętu; potrzeba przechowywania w bezpieczny sposób wrażliwych danych biometrycznych użytkowników.
- **Miejsce, w którym przebywasz (ang. *somewhere you are*)** - metoda sprawdzająca fizyczną lokację użytkownika. Jest to do pewnego stopnia możliwe poprzez sprawdzenie źródłowego adresu IP, współrzędnych GPS urządzenia, czy też na podstawie stacji bazowych w przypadku urządzeń GSM. Należy jednak pamiętać, że dane tego typu mogą zostać podstawione (*spoofing*), więc ten czynnik powinien stanowić jedynie dodatkową ochronę.
- **To, jak się zachowujesz (ang. *something you do*)** - weryfikacja na podstawie wzorców zachowań danego użytkownika, np. sposobu posługiwania się myszką, klawiaturą, ekranu dotykowego, czy też sposobu korzystania z danej aplikacji. Ta metoda, m.in. ze względu na swoją nieprecyzyjność, również powinna być traktowana jedynie jako czynnik wspierający.
## Authenticating systems
W rozbudowanych systemach nie tylko człowiek wymaga potwierdzenia swojej tożsamości. Zdarza się, szczególnie w środowiskach rozproszonych, że **dwie usługi (ang. *services*) muszą się ze sobą komunikować**.

Weźmy jako przykład system sprzedażowy, w którym jedna z usług, odpowiedzialna za przetwarzanie płatności, wywołuje API (np. przez protokół HTTP) innej usługi, obsługującej przygotowanie i wysłanie towaru. Chcemy mieć jednak pewność, że tylko zaufana część naszego systemu (m.in. ta, która jest w stanie potwierdzić otrzymanie zapłaty) była w stanie uruchomić procedurę wysyłki. Usługa odpowiedzialna za wysyłkę musi więc jakoś potwierdzić tożsamość nadawcy żądania, który w tym przypadku nie jest człowiekiem, a inną usługą.

Teoretycznie można wykorzystać w tym celu hasło bądź inny **klucz API**, który jest weryfikowany po stronie odbiorcy żądania. Stwarza to jednak dodatkowe problemy z zakresu bezpieczeństwa, ponieważ zarówno klient (usługa wysyłająca żądanie) oraz serwer (usługa przyjmująca i obsługująca żądanie) muszą gdzieś **przechowywać dane dostępowe, w taki sposób, żeby te przez przypadek nie wyciekły**. Najczęstszym przykładem takiego wycieku jest omyłkowe dołączenie danych uwierzytelniających do repozytorium z kodem aplikacji.

Oczywiście nie oznacza to, że nie stosuje się takiej formy uwierzytelnienia. Należy jednak zachować przy tym szczególną ostrożność i **dane uwierzytelniające, automatycznie wysyłane przez aplikację bądź usługę, przechowywać w przeznaczonym do tego miejscu**. Wiele rozwiązań umożliwiających zarządzanie środowiskiem rozproszonym oferuje narzędzia, które pozwalają na bezpieczne przechowywanie wrażliwych danych (np. [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/), [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault)).

Jeśli korzystamy z rozwiązań chmurowych, często mamy do dyspozycji narzędzia, które umożliwiają uwierzytelnienie pomiędzy usługami, bez konieczności jawnego posługiwania się danymi dostępowymi w postaci haseł, kluczy czy sekretów. Przykładem takiego rozwiązania jest [Azure Managed Identities](https://www.youtube.com/watch?v=sA_mXKy_dKU).

Innym przykładem jest **potrzeba nadania dostępu do sieci organizacji jedynie zaufanym urządzeniom**. Pracownik, aby uzyskać dostęp do firmowej sieci VPN, nie tylko jest zobligowany do podania swoich danych dostępowych, ale może to zrobić jedynie za pośrednictwem służbowego laptopa.

W tym konkretnym przypadku, rozwiązaniem może być umieszczenie **cyfrowo podpisanego certyfikatu na urządzeniu** (laptop pracownika z przykładu). **Taki certyfikat, wygenerowany i podpisany przez organizację, jest później weryfikowany podczas próby połączenia się z siecią**. Dzięki temu, oprócz danych samego użytkownika (pracownika), sprawdzamy również, czy połączenie nawiązano z zaufanego urządzenia, nad którym mamy kontrolę do pewnego stopnia (np. wiemy, że przed wydaniem sprzętu zainstalowano w systemie oprogramowanie typu *anti-malware*).
## Authorization models
Kiedy użytkownik bądź usługa (każdy byt, który przechodzi proces uwierzytelnienia, można określić zbiorczym terminem: *identity*) potwierdzą swoją tożsamość, trzeba jeszcze sprawdzić, do jakich zasobów mają dostęp. Mówiąc krótko: czas na autoryzację.

Najprostszym podejściem, ale też trudnym w utrzymaniu, jest nadawanie konkretnych uprawnień do wybranych zasobów na poziomie uwierzytelnionego konta. Na przykład, jawnie definiujemy, że konto użytkownika *menadżer* może odczytać arkusze kalkulacyjne, zawierające informacje o wysokości wynagrodzeń pracowników danego departamentu. Jeśli konto menadżera mogłoby modyfikować wspomniane arkusze, potrzebne jest kolejne uprawnienie, tym razem do edycji, i tak dalej. Kiedy chcemy nadać identyczne uprawnienia dyrektorowi departamentu, znowu musielibyśmy je definiować dla kolejnego konta.

Takie podejście jest mało efektywne, szczególnie jeśli w naszej organizacji musimy zarządzać setkami (jeśli nie tysiącami) kont reprezentujących określoną tożsamość (dla uproszczenia, w dalszej części tekstu, będziemy posługiwać się terminem *konto użytkownika*). Podobnie jest z zasobami, których w organizacji może być ogromna ilość. Dlatego stosuje się odpowiednie **modele autoryzacji, będące warstwą pośredniczącą pomiędzy uwierzytelnionymi użytkownikami/usługami, a chronionym zasobami.**

**Model autoryzacji można więc potraktować jako warstwę abstrakcyjną, która pozwala odseparować konta użytkowników od informacji, do których próbują uzyskać dostęp.** Dzięki temu, nie mamy bezpośredniego powiązania pomiędzy poszczególnymi użytkownikami i zasobami, przez co łatwiej jest zarządzać dostępem.

Lista najpopularniejszych modeli autoryzacji, które zostaną opisane bardziej szczegółowo przy okazji omawiania zagadnienia *Access Control* (rozdział 4.6 w rozpisce egzaminacyjnej SY0-701):
- ***Role-Based Access Control* (RBAC)** - dostęp jest przyznawany na podstawie ról, które mają zdefiniowane odpowiednie zestawy uprawnień. Następnie, te role są przypisywane użytkownikom.
- ***Attribute-Based Access Control* (ABAC)** - dostęp jest przyznawany na podstawie atrybutów (cech charakterystycznych) użytkownika; środowiska, w którym przechowywane są zasoby; urządzenia, z którego korzysta dany użytkownik. Pozwala na tworzenie rozbudowanych reguł dostępowych uwzględniających wiele atrybutów oraz zapewnia bardziej granularną kontrolę niż model RBAC i często stanowi jego dopełnienie.
- ***Relationship-Based Access Control* (ReBAC)** - decyzje dotyczące dostępu opierają się na relacjach między użytkownikami/zasobami. Na przykład: menadżer ma dostęp do zasobów należących do członków swojego zespołu.
- ***Mandatory Access Control* (MAC)** - dostęp jest ściśle regulowany przez polityki organizacyjne, bez swobody użytkownika w zmienianiu dostępu, nawet w stosunku do zasobów, które sam utworzył.
- ***Discretionary Access Control* (DAC)** - dostęp jest kontrolowany przez właściciela zasobu, który może swobodnie nadawać uprawnienia innym użytkownikom.

Projektując rozwiązania w naszej organizacji, powinniśmy się dobrze zastanowić i **wybrać odpowiedni model autoryzacji**, który będzie najbardziej dopasowany do naszych potrzeb. Warto przy tym wziąć pod uwagę następujące czynniki:
- **Wymagany poziom bezpieczeństwa** - inaczej potraktujemy wrażliwe dane osobowe, a inaczej listę zakupów. Pamiętajmy, że niektóre modele są bardziej restrykcyjne niż pozostałe.
- **Wygoda użytkowników** - wybrany model powinien zapewniać odpowiedni poziom bezpieczeństwa, ale też nie powinien niepotrzebnie utrudniać pracy pracownikom.
- **Złożoność** - jeśli nasze wymagania są specyficzne i rozważamy skomplikowane scenariusze, powinniśmy się zastanowić nad modelami, które oferują większą kontrolę.
- **Skalowalność** - na początku proste modele wydają się być wystarczające, jednak miejmy na uwadze, że organizacja będzie się rozwijać i może okazać się, że musimy szybko dostosować się do nowych realiów.
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
- [PushSec: Brak znajomości CIA wstrzymywał moją karierę](https://pushsec.pl/brak-znajomosci-cia-wstrzymywalo-moja-kariere/)
- [Fortinet: What Is AAA Security?](https://www.fortinet.com/resources/cyberglossary/aaa-security)
- [TechTarget: What is authentication, authorization and accounting (AAA)?](https://www.techtarget.com/searchsecurity/definition/authentication-authorization-and-accounting)
- [Sunny Classroom: AAA framework and RADIUS](https://www.youtube.com/watch?v=feHpDc1cLXM)
- [The Infosec Academy: How RADIUS Authentication Works](https://www.youtube.com/watch?v=LLrb3em-_po)
- [Na Styku Sieci: AAA, RADIUS i TACACS+ – podstawy](https://www.nastykusieci.pl/aaa-radius-tacacs/)
- [Fred B. Schneider: Authentication of People](https://www.cs.cornell.edu/courses/cs513/2007fa/paper.chptr05.pdf)
-  [The Different Types of Authorization Models](https://www.keepersecurity.com/blog/2024/03/19/the-different-types-of-authorization-models/)
