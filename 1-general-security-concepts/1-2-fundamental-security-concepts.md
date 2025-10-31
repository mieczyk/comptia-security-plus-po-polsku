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
# Gap analysis
*Gap analysis* to szeroki termin stosowany w zarządzaniu, który w dosłownym tłumaczeniu oznacza *analizę luk*. Jest to **proces polegający na identyfikacji oraz analizie różnic pomiędzy stanem obecnym, a pożądanym**.

W obszarze bezpieczeństwa IT, analiza luk (ang. *security gap analysis*) sprowadza się do **ustalenia, jakie [środki bezpieczeństwa](https://vilya.pl/sy0-701-security-controls-pl/) (ang. *security controls*) należy wdrożyć bądź poprawić w naszej organizacji, żeby osiągnąć pożądany stan bezpieczeństwa, zdefiniowany na podstawie ustalonych wytycznych**. Innymi słowy, porównujemy aktualnie stosowane środki, z tymi, które trzeba docelowo wdrożyć. Zidentyfikowane odstępstwa powinniśmy potraktować jako potencjalne ryzyko, którym należy się niezwłocznie zająć, jeśli tylko dostępne zasoby na to pozwalają.

Prawidłowo przeprowadzona analiza jest procesem złożonym, ponieważ **uwzględnia aspekty bezpieczeństwa dotyczące różnych obszarów organizacji** (systemy, polityki bezpieczeństwa, pracownicy) oraz wymaga dużego nakładu pracy badawczej, szczególnie jeśli robimy to po raz pierwszy.

Różne poziomy organizacji wymagają przeważnie różnych środków bezpieczeństwa. Przykładowo, w przypadku zasobów ludzkich możemy spróbować oszacować obecny stan wiedzy pracowników nt. zasad bezpieczeństwa IT obowiązujących w firmie i jeśli okaże się niewystarczający, powinniśmy przeprowadzić stosowne szkolenia. Natomiast dla systemów i usług możemy sprawdzić, czy na pewno wdrożyliśmy odpowiednie rozwiązania, stosowane obecnie w branży (np. czy używamy odpowiedniego algorytmu hashującego do obliczania skrótów haseł, przechowywanych w bazie danych).

Osoby odpowiedzialne za bezpieczeństwo informacji w firmie, powinny cyklicznie przeprowadzać procedury *gap analysis*, żeby stale monitorować stan aktualnie używanych środków bezpieczeństwa. Warto przy okazji wspomnieć, że sam proces analizy luk wydaje się bardzo podobny do procesu analizy ryzyka (ang. *risk assessment*). Są to jednak dwie odrębne procedury, ponieważ *gap analysis*, oprócz wskazania istniejących *niedociągnięć*, skutkuje również dokładnym planem działania wraz z kosztami jego wdrożenia.

Proces analizy luk może okazać się dużym wyzwaniem, ponieważ nie ma na to jednej, uniwersalnej procedury. Jednakże działania podejmowane przez różne podmioty, bardzo często mają wspólne elementy, opisane poniżej.
## 1. Określenie stanu docelowego
To, do czego dąży dana organizacja pod względem bezpieczeństwa IT, zależy tak naprawdę od samej organizacji - jej celów, obszarów działalności, regulacji prawnych itp. Oznacza to, że każda firma może zupełnie inaczej zdefiniować stan docelowy, co wymaga indywidualnego podejścia do procesu *gap analysis*.

Nic jednak nie stoi na przeszkodzie, żeby wykorzystać w tym celu znane i cenione w branży standardy bezpieczeństwa IT, takie jak [ISO/IEC 27001](https://www.iso.org/standard/27001) lub [NIST SP 800-171](https://csrc.nist.gov/pubs/sp/800/171/r3/final). Dążenie do zgodności z formalnymi standardami jest często niezbędne dla wielu firm, jeśli planują one uzyskać określony certyfikat, który z kolei umożliwi branie udziału w niektórych przetargach. Nie wspominając o prawnych wymogach zgodności z wybranymi standardami dla instytucji działających w obszarach, gdzie bezpieczeństwo informacji jest krytyczne.
## 2. Zebranie informacji o aktualnym stanie
Kiedy mamy już zdefiniowane wytyczne, czas na rzetelną ocenę obecnej sytuacji i zebranie szczegółowych informacji o aktualnie stosowanych środkach bezpieczeństwa.

Punktem wyjściowym do tego, jakie konkretnie dane należy zebrać oraz z jakich obszarów (m.in. systemy, procedury, pracownicy), może być dokument z ustalonymi wcześniej wytycznymi. Na przykładzie oficjalnego dokumentu [NIST SP 800-171r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf), zatytułowanego *Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations*, widzimy szerokie obszary związane z bezpieczeństwem IT, które są podzielone na węższe kategorie. Natomiast w ramach wybranych kategorii znajdziemy ogólne opisy dopasowanych środków bezpieczeństwa.

Na przykład, powyższy dokument zawiera bardzo ogólną sekcję *3.1 Access Control* (kontrola dostępu), która jest podzielona na wiele różnych aspektów związanych z ochroną dostępu do informacji. Dwa z nich to:
- *03.01.01 Account Management* - znajdziemy tutaj opis powszechnie stosowanych metod zarządzania kontami użytkowników w systemach i aplikacjach, gdzie istotny jest kontrolowany dostęp do zasobów.
- *03.01.05 Least Privilege* - opisuje w ogólny sposób, jak należy poprawnie wdrożyć zasadę najmniejszego uprzywilejowania.

Dzięki rozbiciu rozległych obszarów na mniejsze elementy, dużo łatwiej jest stworzyć plan działania i monitorować postępy.
## 3. Przygotowanie szczegółowego raportu
Wszystkie zebrane do tej pory informacje powinniśmy zawrzeć w **dokumencie podsumowującym, który zaprezentuje w czytelny sposób różnice pomiędzy sytuacją obecną i pożądaną**. Do prostej wizualizacji stanu faktycznego często używa się kolorów, na przykład:
- Kolorem zielonym można oznaczyć te obszary, które już pokrywają się z postawionymi celami.
- Kolor żółty przedstawiałby obszary, w których docelowe wymagania są częściowo spełnione, ale wymagają jeszcze dopracowania.
- Kolor czerwony oznaczałby całkowity bądź częściowy brak oczekiwanych środków bezpieczeństwa.

Poniżej znajduje się wycinek z przykładowego raportu. Należy oczywiście pamiętać, że każda organizacja może posiadać odmienne potrzeby, cele oraz priorytety, więc także dokumentacja może wyglądać zupełnie inaczej, niż ta przedstawiona w poniższym przykładzie.

![Gap analysis example](https://github.com/mieczyk/comptia-security-plus-po-polsku/blob/main/media/1-2-gap-analysis-example.png)
Źródło: opracowanie własne.

Kiedy już posiadamy zestawienie aktualnego stanu środków bezpieczeństwa z docelowymi, **powinniśmy w ostatecznym raporcie określić konkretne działania prowadzące do zniwelowania wykrytych różnic. Dysponując listą zdefiniowanych kroków, jesteśmy również w stanie oszacować koszty ich realizacji**. W powyższym przykładzie podano jedynie ogólne działania, jakie należy podjąć. W pełnym raporcie końcowym można zawrzeć bardziej szczegółowy plan wdrożenia. Oczywiście w taki sposób, żeby pełna dokumentacja zachowała niezbędną czytelność.

Podsumowując, pełny raport z procesu analizy luk powinien (w większości przypadków) zawierać następujące elementy:
- Wprowadzenie, informujące o zakresie oraz intencji procesu analizy.
- Wymagania, które należy spełnić, żeby osiągnąć docelowy standard bezpieczeństwa.
- Lista środków bezpieczeństwa, które są aktualnie stosowane, wraz z ich obecnym stanem.
- Informacje o tym, które z obecnych środków wymagają dostosowania. Jeśli w danym obszarze w ogóle brakuje odpowiednich zabezpieczeń, również należy o tym zakomunikować i zaproponować odpowiednie rozwiązania.
- Przewidywany czas realizacji (np. drugi kwartał bieżącego roku).
- Konkretne kroki, które należy podjąć, żeby osiągnąć wyznaczone cele.
# Zero Trust
Wykaz skrótów używanych w opracowaniu zagadnienia *Zero Trust*:
- **ZT** = *Zero Trust*.
- **PEP** = *Policy Enforcement Point*.
- **PDP** = *Policy Decision Point*.
- **PA** = *Policy Administrator*.
- **PE** = *Policy Engine*.

---
**Model bezpieczeństwa *zero trust*** (w wolnym tłumaczeniu: *nie ufaj nikomu i niczemu*) **opiera na zasadzie nieustannej kontroli dostępu do chronionych zasobów, również w przypadku użytkowników i urządzeń, którzy już nawiązali połączenie z siecią wewnętrzną**.

Nawet dziś, w wielu firmach, można spotkać się z założeniem, że jeśli użytkownik przeszedł pomyślnie proces weryfikacji (podał prawidłowe dane uwierzytelniające) i uzyskał dostęp do sieci organizacji, to znaczy, że na pewno jest tym, za kogo się podaje. Dalsza weryfikacja poczynań takiego użytkownika wydaje się być zbędna - w końcu przeszedł proces uwierzytelnienia, kiedy łączył się z siecią.

Tradycyjne modele bezpieczeństwa, takie jak [*castle-and-moat*](https://www.cloudflare.com/learning/access-management/castle-and-moat-network-security/) (w dosłownym tłumaczeniu: *zamek z fosą*), polegające na solidnej ochronie dostępu samej do sieci, ale pełnym zaufaniu wszystkiemu co już jest w środku, rzeczywiście mogły być wystarczające w czasach, gdy sieć oraz niemalże wszystkie zasoby organizacji (także pracownicy) znajdowały się *na miejscu* (*on-premise*). Jednakże w dobie rozproszonych usług chmurowych, wszechobecnej pracy zdalnej, a także rozbudowanych ataków, często opierających się na wyrafinowanych [metodach socjotechnicznych](https://vilya.pl/sy0-601-cheatsheet-1-1-social-engineering/), takie podejście przestaje być skuteczne.

Można oczywiście zastosować dodatkowe strategie obronne, takie jak [*defence-in-depth*](https://www.cloudflare.com/learning/security/glossary/what-is-defense-in-depth/) (inna nazwa: *layered security*), gdzie, jak sama nazwa wskazuje, wdraża się techniki zabezpieczające na różnych warstwach infrastruktury IT organizacji. Na przykład: warstwa sieciowa jest chronione przez firewalle oraz systemy IDS/IPS; cały ruch w sieci wewnętrznej jest szyfrowany; aplikacje wytwarza się zgodnie z standardami [SSDLC (*Secure Software Development Lifecycle*)](https://snyk.io/articles/secure-sdlc/); wszystkie urządzenia pracowników są pod ochroną oprogramowania typu *anti-malware* itd.

Oba wymienione wyżej podejścia, nawet jeśli są stosowane nierozłącznie, mają jedną słabość: jeśli intruzowi uda się w jakiś sposób pokonać wszystkie zabezpieczenia i uzyskać dostęp do chronionych zasobów, jest duża szansa, że tak już zostanie. Od tego momentu atakujący jest traktowany jako byt zaufany i może kontynuować swoją szkodliwą działalność, jeśli tylko uda mu się dobrze ukryć.

Załóżmy, że pracujący zdalnie członek organizacji, z dosyć dużymi uprawnieniami, codziennie łączy się z firmą za pośrednictwem sieci VPN. Kiedy już się uwierzytelni i nawiąże połączenie, posiada szeroki dostęp do różnych istotnych zasobów organizacji. Teraz wystarczy jedynie *wyciągnąć* dane uwierzytelniające od takiego pracownika i się pod niego podszyć bądź *nakłonić* go do zainstalowania złośliwego oprogramowania na sprzęcie firmowym. Od tej chwili intruz ma praktycznie takie same możliwości, co zaatakowany pracownik.

Paradygmat *zero trust* (ZT) wydaje się być remedium na wspomniane bolączki, ponieważ **zakłada równe traktowanie podmiotów (użytkownicy, systemy, usługi, aplikacje, którzy próbują uzyskać dostęp) działających wewnątrz sieci oraz podmiotów zewnętrznych**.
Innymi słowy, **nawet jeśli użytkownikowi udało się połączyć z siecią organizacji, to każde jego żądanie dostępu (ang. *access request*) do chronionego zasobu będzie weryfikowane tak samo skrupulatnie, jak w przypadku kogoś spoza sieci**. Sprawdzanie każdego żądania często nazywamy ciągłą weryfikacją (ang. *continuous validation*) bądź ciągłym uwierzytelnianiem (ang. *continuous authentication*) i nawet jeśli podmiot otrzyma dostęp do żądanego zasobu, to tylko na ograniczony czas trwania sesji.

Sam proces weryfikacji w podejściu *zero trust* jest dosyć złożony. Oprócz danych uwierzytelniających (ang. *credentials*) brane są pod uwagę dodatkowe czynniki, takie jak: źródłowy adres IP podmiotu; czy system operacyjny, z którego przychodzi żądanie, jest odpowiednio zabezpieczony; w jakim czasie nawiązano połączenie lub z jakiego miejsca itd. Jeśli któryś z weryfikowanych atrybutów będzie wyglądał podejrzanie (np. żądanie dostępu przyjdzie w środku nocy z egzotycznego kraju), to użytkownik bądź aplikacja mogą zostać poddani dodatkowej kontroli, a w przypadku bardziej restrykcyjnej polityki bezpieczeństwa, dostęp zostanie całkowicie zablokowany.

Kluczowe zasady podejścia *zero trust*:
1. **Bezustanny monitoring (ang. *continuous monitoring*) i ciągła weryfikacja (ang. *continuous validation*)** - zakładamy, że atak może przyjść zarówno z zewnątrz, jak i z wewnątrz organizacji. Dlatego każdy użytkownik czy urządzenie są stale i ściśle kontrolowani. Oprócz danych dostępowych sprawdza się dodatkowe atrybuty podmiotu. Weryfikowany jest każdy *request*, a połączenia, które już uzyskały dostęp, są co jakiś czas restartowane, żeby wymusić ponowną kontrolę.
2. ***Least privilege*** - podmiot ma dostęp jedynie do tych zasobów, których rzeczywiście potrzebuje i nic ponadto. Nawet jeśli intruzowi uda się przejąć konto zaufanego użytkownika, ewentualne szkody będą ograniczone do możliwości zaatakowanego konta.
3. **Kontrola dostępu urządzeń (ang. *device access control*)** - polega na dokładnym sprawdzaniu, ile różnych urządzeń próbuje połączyć się z siecią, czy są one odpowiednio zabezpieczone oraz czy nie zostały wcześniej skompromitowane. Należy pamiętać, że tak szczegółowa kontrola nie zawsze jest możliwa w przypadku urządzeń typu BYOD (*Bring Your Own Device*), które nie są własnością organizacji.
4. **Zapobieganie *lateral movements*** (spotkałem się z tłumaczeniem *ruch boczny*, ale bardzo mnie to kłuje, więc zostańmy przy oryginalnej wersji) - polega na uniemożliwieniu dalszych działań intruzowi, który zdołał przekroczyć granicę sieci (ang. *network perimeter*). Jest to bezpośrednio związane z zasadą *least privilege* i obejmuje również takie działania jak **segmentacja sieci** (ang. *network segmentation*), czyli jej podział na mniejsze, odizolowane obszary, oraz **mikrosegmentacja** (ang. *microsegmentation*), czyli bardziej precyzyjna forma podziału - na poziomie pojedynczych serwerów, aplikacji, a nawet procesów. Mówiąc krótko: intruz zostanie ograniczony do jednej strefy.
5. **MFA (*Multi-Factor Authentication*)** - stosowanie uwierzytelniania wieloskładnikowego powinno być już w zasadzie standardem i to nie tylko w podejściu *zero trust*. Należy również mieć na uwadze fakt, że hardware'owe klucze bądź kody generowane bezpośrednio na urządzeniu są przeważnie bezpieczniejsze niż te generowane przez oprogramowanie działające na serwerze i wysyłane np. SMS-em.
6. ***Threat Intelligence*** - aktywna obserwacja przeróżnych baz wiedzy pod kątem potencjalnych zagrożeń i dostosowywanie polityk bezpieczeństwa do bieżących potrzeb. Pamiętajmy, że niemalże codziennie pojawiają się nowe niebezpieczeństwa, a te już znane często ewoluują.
7. ***Assume breach*** - to założenie, że prędzej czy później nastąpi **udany** atak, o ile już się nie wydarzył. 

Wybrane korzyści modelu *zero trust*:
- Redukcja liczby potencjalnych zagrożeń, a także minimalizowanie potencjalnych szkód w razie udanego ataku (zarówno zewnętrznego, jak i wewnętrznego).
- Sprawdzanie każdego żądania do chronionych zasobów ogranicza dostęp dla urządzań, które mogą być podatne na ataki. Jest to szczególnie istotne dla urządzeń IoT (*Internet of Things*), gdzie aktualizacje oprogramowania pojawiają się znacznie rzadziej niż w przypadku standardowych stacji roboczych (laptopy, komputery PC) i urządzeń mobilnych (smartfony, tablety).
- Zwiększona widoczność i kontrola nad tym, co dzieje się w sieciach organizacji.
- Wdrożenie architektury *zero trust* (ZTA = *Zero Trust Architecture*) bardzo często pomaga osiągnąć zgodność (ang. *compliance*) z wybranymi standardami bezpieczeństwa, takimi jak HIPAA (*Health Insurance Portability and Accountability Act*), GDPR (*General Data Protection Regulation*) czy PCI DSS (*Payment Card Industry Data Security Standard*). Warto zaznaczyć, że sam model ZT nie jest wymagany przez wspomniane standardy branżowe, ale jego implementacja narzuca pewne mechanizmy, które mogą być konieczne.

Wdrożenie architektury *zero trust* to złożony i długotrwały proces, który stawia przed zespołami IT wiele wyzwań. Niewiele organizacji może sobie pozwolić na stworzenie odpowiednio dostosowanej infrastruktury od podstaw, dlatego jeśli zdecydujemy się na taki kierunek, warto dokładnie zaplanować poszczególne etapy migracji i rozłożyć je w czasie. Zaleca się, aby pierwszym krokiem było wybranie najmniej krytycznego (z punktu widzenia działania biznesu) obszaru infrastruktury IT i przetestowanie na nim nowego podejścia, zanim przejdziemy do kolejnych działań. Dzięki temu zdobędziemy niezbędne doświadczenie i zidentyfikujemy problemy, których nie byliśmy w stanie przewidzieć na etapie planowania.

Pamiętajmy również, że nazwa *zerowe zaufanie* to w rzeczywistości hiperbola. Należy znaleźć złoty środek pomiędzy absolutnym bezpieczeństwem a funkcjonalnością i wygodą. Kiedy użytkownicy naszych systemów napotykają zbyt restrykcyjne reguły bezpieczeństwa, które znacząco utrudniają im pracę, zaczynają intensywnie kombinować, jak je obejść. Nawet jeśli pracownicy organizacji będą musieli częściowo zrezygnować z pewnych udogodnień, należy ich odpowiednio uświadomić, dlaczego jest to istotne i co dzięki temu zyskujemy.

Bardzo prosty i ciekawy przykład implementacji modelu *zero trust* został przedstawiony na nagraniu: [Zero Trust Explained | Real World Example](https://www.youtube.com/watch?v=Y3DjoTiOiOU&ab_channel=CertBros). Pokazano tutaj, na przykładzie rozwiązania [Twingate](https://www.twingate.com/), w jaki sposób można wykorzystać technologię [ZTNA](https://www.cloudflare.com/learning/access-management/what-is-ztna/) (*Zero Trust Network Access*) do szczegółowej kontroli dostępu do urządzenia NAS (*Network Attached Storage*), zainstalowanego w sieci prywatnej.

Jeśli chcemy wdrażać poważniejsze systemy, powinniśmy zrozumieć w jaki sposób urządzenia sieciowe odpowiedzialne za bezpieczeństwo (fizyczne i wirtualne) dzielą się na **warstwę sterowania** (ang. ***control plane***) oraz **warstwę danych** (ang. ***data plane*** lub *forwarding plane*). Szczegóły podziału omówimy poniżej, ale żeby mieć ogólny pogląd, wyobraźmy sobie samochody jeżdżące po miejskich drogach. Poruszające się pojazdy stanowią warstwę danych (jak pakiety danych przemierzające sieć), a znaki i sygnalizacje świetlne są częścią warstwy sterowania (podobnie jak routery, switche i firewalle sterujące ruchem sieciowym).

Przyjrzyjmy się ogólnemu diagramowi reprezentującemu ideę architektury *zero trust* (uwaga: schemat pokazuje jedynie logiczny podział elementów architektury ZT i jej fizyczna realizacja może się różnić):

![Zero Trust diagram - NIST](https://github.com/mieczyk/comptia-security-plus-po-polsku/blob/main/media/1-2-zero-trust-diagram-NIST.png)
Źródło: [NIST SP-800-207 - Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf). Wersję polską można ściągnąć tutaj: [NSC 800-207](https://www.gov.pl/attachment/8659d8de-6a83-4860-bcd1-d0648fbe9ead) (jest trochę starsza i w mojej ocenie niezbyt trafnie przetłumaczona).

Podmiot (ang. *subject*) próbuje uzyskać dostęp do zasobu organizacji (ang. *enterprise resource*) z niezaufanego systemu. Każde żądanie dostępu przechodzi przez punkt kontrolny, zwany *Policy Enforcement Point* (PEP), którego zadaniem jest przepuszczanie wyłączne w pełni uwierzytelnionych i autoryzowanych zapytań. PEP nie podejmuje jednak decyzji samodzielnie - za to odpowiada *Policy Decision Point* (PDP), czyli komponent, w którym następuje pełna weryfikacja i zapada werdykt, czy dany podmiot ma prawo uzyskać dostęp do chronionego zasobu. Proces decyzyjny może uwzględniać wiele czynników, co zostało pokazane na powyższym schemacie, ale wrócimy do tego w dalszej części opracowania. Ostatecznie, PEP otrzymuje odpowiedź z PDP i na jej podstawie ustanawia połączenie podmiotu z docelowym zasobem lub je odrzuca.
## Control Plane
**Warstwa sterowania (ang. *control plane*) jest częścią sieci kontrolującą to, w jaki sposób dane są przez tę sieć przesyłane i przekazywane**. Zaliczamy do niej m.in. tabele routingu, zawierające informacje o trasie do adresu docelowego; polityki dostępu; reguły zdefiniowane na firewallach; tłumaczenia adresów NAT (*Network Address Translation*). Mówiąc krótko: **są to wszystkie elementy, które odpowiadają za sterowanie ruchem w sieci**.

W architekturze *zero trust* w skład warstwy sterowania wchodzą 4 komponenty, opisane poniżej.
### Adaptive identity
*Adaptive identity* (inna nazwa: *adaptive authentication*) można przetłumaczyć dosłownie jako *adaptacyjna tożsamość*. Koncept ten zakłada **weryfikację tożsamości, która nie opiera się jedynie na danych uwierzytelniających, przekazanych przez użytkownika, ale bierze pod uwagę także dane kontekstowe i inne atrybuty tego użytkownika**. Mogą to być takie informacje jak:
- Źródłowy adres IP podmiotu próbującego uzyskać dostęp do zasobów sieciowych.
- Miejsce, z którego łączy się użytkownik (geolokalizacja).
- Czas połączenia (np. czy ktoś próbuje łączyć się poza standardowymi godzinami pracy).
- Dane o urządzeniu, z którego łączy się użytkownik (np. czy posiada aktualną wersję oprogramowania; czy jest prawidłowo skonfigurowane; czy zainstalowano na nim oprogramowanie typu *anti-malware*).
- Relacja z organizacją: czy użytkownik jest pełnoetatowym pracownikiem, podwykonawcą czy kontrahentem?
- Wszystkie pozostałe wskazówki, które pomogą w identyfikacji podmiotu (np. wzorce zachowań).

**Podejście adaptacyjne zakłada dostosowanie środków bezpieczeństwa do zaistniałej sytuacji, ocenianej na podstawie otrzymanych danych uwierzytelniających oraz zgromadzonych informacji kontekstowych**. Oznacza to, że system (a dokładnie PEP) może zażądać od użytkownika wykonania dodatkowych kroków celem uwierzytelnienia, gdy nastąpi jakaś anomalia bądź całkowicie odrzucić żądanie, jeśli polityki nie zezwalają na dodatkową weryfikację.

Na przykład: jeżeli pracownik firmy znajdującej się w USA nawiązał połączenie z adresu IP zlokalizowanego w Chinach (a wczoraj wieczorem widziano go w biurze, w Nowym Jorku), to sytuację można uznać za mocno podejrzaną. W tym momencie, zgodnie z podejściem ZT, takie połączenie powinno zostać całkowicie zablokowane bądź należy zażądać od użytkownika dodatkowego uwierzytelnienia, w zależności od skonfigurowanej polityki bezpieczeństwa.
### Threat scope reduction
Redukcja obszaru podatnego na zagrożenia (ang. *threat scope reduction*) to nic innego jak **ograniczenie dostępu użytkownika (człowieka bądź systemu) tylko do tych zasobów, które są niezbędne do realizacji jego zadań**. Dzięki temu ograniczamy *pole rażenia* (ang. *blast radius*), jeśli okaże się, że konto zostało skompromitowane i przejęte przez intruza.

 Redukcja zagrożeń bazuje mi.in. na zasadzie *least privilege* oraz na [segmentacji opartej o tożsamość](https://www.silverfort.com/glossary/identity-segmentation/), tj. dostęp do wybranych obszarów sieci bądź zasobów jest przyznawany na podstawie atrybutów użytkownika (np. jego przynależności do działu, roli w organizacji itp.).
### Policy-driven access control
Kontrola dostępu oparta o polityki bezpieczeństwa (ang. *policy-driven access control*) jest kluczowym konceptem podejścia ZT, który został już w dużym stopniu omówiony wcześniej. Dla przypomnienia, w tradycyjnym podejściu podmiot zostaje uwierzytelniony na podstawie danych uwierzytelniających bądź dodatkowych informacji wymuszonych przez MFA. **Kontrola dostępu oparta o polityki pozwala na bardziej szczegółową weryfikację, z uwzględnieniem pełnego kontekstu żądania oraz atrybutów podmiotu**.

Bardziej wyrafinowane rozwiązania nie polegają jedynie na sztywno zdefiniowanych regułach, ale podejmują decyzję o przyznaniu bądź zablokowaniu dostępu w oparciu o dane pochodzące z różnych źródeł (widocznych na powyższym diagramie):
- ***CDM (Continuous Diagnostics and Mitigation) System*** - system monitorujący stan zasobów organizacji, odpowiadający za aktualizację konfiguracji i oprogramowania. Jest w stanie dostarczyć informacje o bezpieczeństwie urządzeń żądających dostępu, zarówno tych należących do przedsiębiorstwa, jak i zewnętrznych, a także wyegzekwować odpowiednie polityki bezpieczeństwa.
- ***Industry Compliance*** - odpowiada za weryfikację i egzekwowanie polityk niezbędnych do zapewnienia zgodności z obowiązującymi przepisami, których musi przestrzegać organizacja.
- ***Threat intelligence*** - źródła informacji (wewnętrzne i zewnętrzne) o najnowszych zagrożeniach, takich jak techniki ataków, wykryte podatności, odmiany złośliwego oprogramowania.
- ***Activity Logs*** - logi zbierane z sieci oraz systemów organizacji.
- ***Data Access Policy*** - reguły definiujące polityki dostępu. Mogą być zdefiniowane *na sztywno* lub wygenerowane dynamicznie. Jest to punkt wyjściowy procesu autoryzacji dostępu do chronionych zasobów.
- ***PKI (Public Key Infrastructure)*** -  system odpowiedzialny za generowanie oraz weryfikację elektronicznych certyfikatów bezpieczeństwa i ogólnie za zarządzanie rozwiązaniami opartymi o kryptografię, stosowanymi w organizacji.
- ***ID Management*** - system zarządzania tożsamością, odpowiedzialny za administrację kontami użytkowników/usług. Tutaj przechowywane są najważniejsze informacje dotyczące określonych kont, włączając w to role i uprawnienia.
- ***SIEM (Security Information and Event Management) System*** - system, który zbiera i agreguje wszystkie informacje oraz zdarzenia związane z bezpieczeństwem. Zgromadzone dane mogą być później prezentowane administratorom w formacie ułatwiającym dalszą analizę.
### Policy Administrator
*Policy Administrator* (PA) to nie jest człowiek, jak może sugerować nazwa, ale komponent będący częścią *Policy Decision Point* (PDP), który **odpowiada za przekazywanie do PEP decyzji, podjętej przez *Policy Engine*, o przyznaniu bądź zablokowaniu dostępu wybranemu podmiotowi**.

Innymi słowy, jeśli podmiot powinien uzyskać dostęp do żądanego zasobu, PA *mówi* o tym PEP, **udostępniając jednocześnie niezbędne dane uwierzytelniające, tokeny dostępu bądź klucze sesji wymagane do nawiązania połączenia z zasobem**. W innym przypadku (brak dostępu), nakazuje PEP zakończyć bieżącą sesję (połączenie).
### Policy Engine
*Policy Engine* (PE) to drugi element PDP, który **analizuje żądania przechodzące przez PEP pod kątem zdefiniowanych reguł, polityk bezpieczeństwa oraz wszystkich danych zebranych z innych komponentów całego systemu** (np. SIEM, dzienniki zdarzeń) **i podejmuje ostateczną decyzję o przyznaniu (ang. *grant*), odrzuceniu (ang. *deny*) bądź cofnięciu (ang. *revoke*) dostępu**.

Decyzja o przyznaniu dostępu jest podejmowana przez odpowiednie algorytmy zaufania (ang. *Trust Algorithms*), które na wejściu przyjmują dane z wielu źródeł, opisanych krótko w paragrafie *Policy-driven access control*. Każda taka decyzja jest zapisana w właściwym dzienniku (log) oraz przekazana do PEP za pośrednictwem PA.
## Data Plane
*Data plane* (warstwa danych), nazywana również *forwarding plane*, **jest częścią infrastruktury sieciowej odpowiedzialną za przesyłanie i przetwarzanie danych. Zaliczamy do niej urządzenia przesyłające i przetwarzające dane sieciowe w czasie rzeczywistym**, czyli m.in. switche, routery, firewalle.

Zwróćmy uwagę, że granica między warstwą danych oraz warstwą sterowania jest abstrakcyjna i jedno urządzenie może należeć do obu płaszczyzn. Przykładowo: router sieciowy przekazuje pakiety do odpowiedniego miejsca docelowego (warstwa danych) i robi to na podstawie zapisanych u siebie tabel routingu (warstwa sterowania).
### Implicit trust zones
Nawet w podejściu *zero trust* nie da się obejść bez pewnej dozy zaufania, jeśli cały system ma być funkcjonalny. **Kiedy podmiot próbujący uzyskać dostęp do chronionego zasobu, spełni wszystkie wymagania procesu uwierzytelnienia i autoryzacji (tj. zostanie przepuszczony przez PEP), trafia do *strefy domyślnego zaufania* (ang. *implicit trust zone*)**. Oznacza to, że przez jakiś czas taki **użytkownik, system, usługa bądź aplikacja są traktowani jako byty zaufane i mają dostęp do elementów znajdujących się w tej strefie** (np. serwer bazodanowy).

Mówiąc krótko: *implicit trust zone* to obszar, gdzie wszystkie podmioty, które się w nim znajdują, otrzymały pewną dozę zaufania od ostatniego punktu kontrolnego PDP/PEP. Taki obszar sieci możemy sobie wyobrazić jako część lotniska, między punktem kontroli bezpieczeństwa (odpowiednik PDP/PEP), a bramkami *strzegącymi* wejścia do samolotu. Wszystkie osoby przebywające w tej strefie (pasażerowie, pracownicy lotniska, załoga) można traktować jako zaufane do pewnego stopnia.

Warto mieć na uwadze, że sam zasób, z którym udało się połączyć, może wymagać dodatkowego uwierzytelnienia. Na przykładzie serwera baz danych: każda baza może mieć skonfigurowanego indywidualnego użytkownika, od którego wymaga się dodatkowo podania loginu i hasła.

Domyślne strefy zaufania powinny być możliwie jak najmniejsze, zgodnie z omówioną wcześniej zasadą *threat scope reduction*. Poza tym, każde przejście z jednej strefy zaufania do drugiej wymaga ponownej weryfikacji (dostęp do niektórych obszarów może być bardziej restrykcyjny niż w przypadku innych).
### Subject/System
Terminy takie jak *podmiot* (ang. *subject*) oraz *system* już przewinęły się w tym tekście niejednokrotnie, więc teraz jedynie przypomnijmy sobie definicje:
- ***Subject* - podmiot, który próbuje uzyskać dostęp do chronionego zasobu i jest weryfikowany przez PDP/PEP**. Często jest to **człowiek, który posługuje się wybranym kontem użytkownika,** ale równie dobrze może to być oprogramowana maszyna. W tym przypadku **podmiotem jest usługa bądź aplikacja**, która łączy się z siecią wykorzystując konto użytkownika automatycznego, nazywane zazwyczaj kontem usługi (ang. *service account*).
- ***System* - urządzenie z systemem operacyjnym, które jest używane przez podmiot do nawiązania połączenia i uzyskania dostępu do chronionych zasobów organizacji**.
### Policy Enforcement Point
*Policy Enforcement Point* (PEP) jest to **punkt w sieci, przez który przechodzą wszystkie żądania dostępu od podmiotów i w zależności od wyników weryfikacji, dostęp jest przyznawany bądź blokowany**.

Jest to rodzaj *strażnika bramy* (ang. *gatekeeper*), który przepuszcza tylko uprawnionych interesantów. **Sam jednak nie podejmuje decyzji**, ponieważ dokładne wskazówki otrzymuje od swojego bezpośredniego *dowódcy*, czyli wspomnianego wcześniej komponentu *Policy Decision Point* (*Policy Administrator* + *Policy Engine*). PDP z kolei wydaje werdykt na podstawie informacji o żądaniu otrzymanych z PEP, zestawionych z instrukcjami pochodzącymi z innych źródeł (np. zdefiniowane polityki dostępu).

Na wykresie PEP jest przedstawiony jako pojedynczy element, ale pamiętajmy, że jest to jedynie abstrakcyjny koncept i funkcjonalność PEP może składać się z wielu rozproszonych elementów.
# Physical security (TODO)
- Kiedy mówimy o bezpieczeństwie informacji, naszą pierwszą myślą są cyfrowe środki bezpieczeństwa. Musimy jednak pamiętać, że część z tych środków może okazać się bezużyteczna, jeśli atakującemu uda się uzyskać fizyczny dostęp do serwera lub stacji roboczej, na których przechowywane są istotne dane.
- Poza tym, w wielu organizacjach, oprócz danych cyfrowych, często przechowywane są ważne dokumenty w formie papierowej, które również wymagają należytej ochrony.
- Fizyczny dostęp do systemów, sieci lub urządzeń jest często najprostszym sposobem na ominięcie wielu wyrafinowanych cyfrowych środków bezpieczeństwa (bezpośredni dostęp do maszyny, kradzież sprzętu czy nieautoryzowane *wpięcie się* do sieci, w której brakuje odpowiedniej weryfikacji wewnętrznego ruchu), więc nie powinniśmy zaniedbywać tego aspektu.
- Pierwszym krokiem powinno być opracowanie planu zabezpieczeń konkretnej placówki (*site security*) - najpierw powinniśmy zidentyfikować miejsca narażone na nadużycia oraz oszacować ryzyko ich wystąpienia, a następnie dobrać adekwatne środki zapobiegawcze.
- Można zauważyć, że wspomniane niżej środki mogą być stosowane na różnych warstwach, podobnie jak omawiane wcześniej [środki techniczne](https://github.com/mieczyk/comptia-security-plus-po-polsku/blob/main/1-general-security-concepts/1-1-security-controls.md#technical).
- Jedną z technik, które mogą wspomóc zabezpieczenie placówki jest maskowanie poprzez umiejscowienie jej na mało znanym i uczęszczanym terenie i/lub zadbanie o niepozorny wygląd budynku. Taki zabieg można określić jako *industrial camouflage*, co w dosłownym tłumaczeniu oznacza *kamuflaż przemysłowy*. Oczywiście nie należy tego traktować jako skuteczną metodę zabezpieczającą, a jedynie jako technikę wspomagającą, opierającą się o zasadę *bezpieczeństwa przez niejawność* (ang. *security through obscurity*).
- Ciekawostka: w dzisiejszych czasach należy brać również pod uwagę drony. Mowa tutaj o jedynie o dronach cywilnych, służących do zwykłego podglądania lub ewentualnego szpiegostwa gospodarczego. Choć dla większości organizacji nie jest to krytyczne zagrożenie, to możemy mieć na uwadze, że takie incydenty również mogą wystąpić. Należy przy tym również pamiętać, że nawet jeśli zbudujemy skuteczny system wykrywania dronów, to ich neutralizacja może nie być taka prosta ze względu na prawo, które chroni taki sprzęt jako własność prywatną.
- Należy mieć na uwadze, że rozpiska egzaminacyjna nie wymienia kilku innych istotnych zabezpieczeń fizycznych, które również są powszechnie stosowane. Są to zamki (mechaniczne lub elektroniczne), alarmy czy też systemy przeciwpożarowe (ang. *fire suppression systems*). 
## Bollards
- Słupy/słupki/pachołki stanowiące rodzaj barykady, uniemożliwiającej fizyczny dostęp do pewnych obszarów placówki. Ich najczęstszym zastosowaniem jest uniemożliwienie wjazdu pojazdom na określony teren (ludzie mogą je bez problemu ominąć pieszo).
	- Jeśli są wyraźnie oznaczone jaskrawymi barwami, mogą również pełnić funkcję ostrzegawczą.
	- Przeważnie wykonane są z solidnych materiałów (beton, metal).
- Zapobiegają zarówno wypadkom jak i celowym atakom z użyciem pojazdu.
## Access control vestibule
- Inna nazwa: *mantrap* (dosłownie: pułapka na ludzi). Można to dosłownie przetłumaczyć jako *przedsionek kontroli dostępu* i jest opisem pomieszczanie, przez które trzeba przejść, żeby uzyskać dostęp do dalszej części placówki. Przykładowo: drzwi do kolejnego pomieszczania nie otworzą się dopóki nie zamkniemy drzwi wejściowych i nie uwierzytelnimy się w odpowiedni sposób (np. przykładając kartę dostępu do czytnika).  Procedura przejścia przez taki przedsionek może się różnić w zależności od potrzeb, ale cel jest jednakowy: kontrola dostępu do wybranego obszaru placówki. Takie pomieszczenie kontrolne może być niewielkie, żeby umożliwić przejście tylko jednej osobie na raz.
- Chyba najpopularniejszą formą takiego przedsionka  jest pomieszczenie z parą drzwi. Pierwsze wejście (z zewnątrz) wymaga jakiejś formy autoryzacji (np. zamek elektroniczny otwierany kartą dostępu). Drugie drzwi, prowadzące do chronionej części placówki, otwierają się dopiero, gdy pierwsze się zamkną.
- To zabezpieczenie chroni przed atakami typu [*tailgating/piggybacking*](https://vilya.pl/sy0-601-cheatsheet-1-1-social-engineering/#tailgating) (w skrócie: osoba nieuprawniona *przykleja się* pod jakimś niepozornym pretekstem do osoby uprawnionej i podąża za nią do miejsc z ograniczonym dostępem).
## Fencing
- Chodzi oczywiście o odpowiednie ogrodzenie. Płoty mogą być różnego rodzaju, w zależności od potrzeb. Nawet niewysokie ogrodzenie pełni funkcję ostrzegawczą lub odstraszającą (*deterrent*). Jeśli płot ma pełnić również funkcję zapobiegawczą, to powinien być trudny do sforsowania, np. wysoki, z drutem kolczastym na górze lub ostrymi zakończeniami (choć trzeba mieć na uwadze panujące w danym kraju przepisy: https://www.rmf.fm/hot-news/news,82153,nowe-przepisy-od-2026-roku-takich-plotow-juz-nie-postawisz.html).
	- Płot może również być nieprześwitujący, żeby ukryć to co się za nim znajduje, choć w erze dronów, taki środek zapobiegawczy może okazać się niewystarczający.
- Rodzaj ogrodzenia będzie w dużej mierze zależny od chronionego obiektu. W przypadku jednostek wymagających wysokiego stopnia bezpieczeństwa, stosowane będą ogrodzenia trudne do sforsowania, których może być też kilka (kilka linii obrony).
## Video surveillance
-  To nic innego jak monitoring za pomocą kamer przemysłowych CCTV (*Closed Circuit TeleVision*). Sieć kamer pozwala na obserwację wielu miejsc placówki jednocześnie z jednego stanowiska (np. z pokoju pracowników ochrony).
	- Oprócz podglądu na żywo oraz zapisu materiału wideo na trwałych nośnikach danych, nowoczesne kamery i korzystające z nich systemy posiadają dodatkowe funkcje, takie jak automatyczne wykrywanie ruchu, które od razu zaalarmuje obserwatora (jest to szczególnie istotne, gdy operator musi nadzorować kamery umieszczone w wielu miejscach); rozpoznawanie twarzy, tablic rejestracyjnych i innych obiektów (jak np. pusta paczka Doritos); wbudowane promienniki podczerwienie, które umożliwiają lepsze *widzenie* po zmroku. Nie wspominając o coraz doskonalszych systemach przetwarzania obrazu opartych na rozwiązaniach AI.
## Security guard
- Same kamery mogą pomóc wykryć nieprawidłowość, ale ktoś musi na taki incydent zareagować i jest to zazwyczaj (a przynajmniej powinien być) odpowiednio przeszkolony i wykwalifikowany pracownik ochrony. Pracownicy ochrony nieraz odpowiadają za weryfikację wchodzących oraz wychodzących na teren organizacji, którzy mogą być pracownikami, klientami bądź odwiedzającymi w określonym celu.
	- Bardzo często sama obecność strażnika, którego stanowisko znajduje się np. przy wejściu do firmy, może odstraszyć *nazbyt ciekawskie* osoby. 
	- Jednym z dodatkowych środków bezpieczeństwa w przypadku pracowników ochrony jest przynajmniej podwójna weryfikacja. Oznacza to, że do wykonania jakiejś czynności może być niezbędne potwierdzenie przez drugiego, uprawnionego pracownika - dzięki temu zmniejszamy ryzyko naruszenia określonych procedur bezpieczeństwa. Doskonałym przykładem takiego podejścia może być konieczność przebywania w kokpicie samolotu przynajmniej dwóch upoważnionych do tego osób (https://polskieradio24.pl/artykul/1409042,lot-wprowadza-wazna-procedure-minimum-dwie-osoby-w-kabinie-pilotow), choć jakiś czas temu pojawiły się pomysły, żeby zrezygnować z tego zabezpieczenia: https://www.rynek-lotniczy.pl/wiadomosci/loty-tylko-z-jednym-pilotem-16089.html
## Access badge
- W praktycznie każdej większej organizacji, osoby przebywające na jej terenie, są zobowiązane do noszenia przy sobie identyfikatora, który często jest również elektroniczną kartą dostępu. Może to być pełnoprawny identyfikator z zdjęciem, nazwiskiem oraz pełnioną funkcją osoby, która jest jego właścicielem, ale może to również być zwykła karta magnetyczna lub z chipem RFID, na którym zapisane są dane identyfikacyjne właściciela. Taka karta jest jednocześnie kluczem do miejsc, do których jej właściciel ma dostęp - odpowiednie czytniki weryfikują dane zapisane na karcie oraz zapisują fakt jej użycia w scentralizowanej bazie danych.
	- Niektóre organizacje mogą wymagać noszenia tych identyfikatorów na widoku, zarówno przez pracowników, jak i przez odwiedzających, którym przydziela się w takim wypadku tymczasowy identyfikator.
- Noszona w widocznym miejscu karta pozwala personelowi, a w szczególności pracownikom ochrony, odróżnić innych pracowników od gości oraz to, czy dana osoba powinna w ogóle w danym miejscu przebywać.
- Podrobienie bądź kradzież takiej karty może stać się dla atakującego przepustką do chronionych miejsc w organizacji, więc wszelkie incydenty związane z utratą karty bądź podejrzenia, że mogła zostać sklonowana, powinny być bezzwłocznie zgłoszone do odpowiedniego działu.
## Lighting
- Twórcy egzaminu najwyraźniej nie zgadzają się z powiedzeniem *najciemniej pod latarnią*, ponieważ wskazują oświetlenie jako jeden z fizycznych środków bezpieczeństwa. W gruncie rzeczy ma to sens - dużo trudniej jest pozostać niezauważonym, gdy obszary, przez które potencjalny włamywacz chce się przemknąć, są dobrze oświetlone. Nawet kamery wykorzystujące technologię podczerwieni (ang. *infrared*, IR) nie mogą się równać z dobrym oświetleniem.
	- Ważny jest również rodzaj oświetlenia, które powinno być równomierne, bez oślepiającego blasku i/lub ciemniejszych obszarów. Jest to szczególnie istotne w przypadku kamer rozpoznających twarze bądź inne obiekty.
- Automatycznie włączane światła, reagujące na ruch, mogą również pełnić funkcję ostrzegawczą, jeśli włączą się w godzinach, w których teoretycznie już nikt nie pracuje.
## Sensors
### Infrared
- Jak zostało wcześniej wspomniane, często stosuje się kamery wykorzystujące IR w celu lepszego widzenia w ciemności. Tego typu urządzenia są w sanie wykryć promieniowanie podczerwieni, niezależnie od warunków oświetleniowych. Czujniki podczerwieni są często stosowane w wykrywaczach ruchu (PIR), szczególnie gdy nie potrzebujemy obrazu wideo i wystarczy nam tylko informacja o tym, czy coś w danym obszarze się poruszyło.
### Pressure
- ****** Czujnik ciśnienia. Może uruchomić alarm, gdy wykryje zmianę w nacisku na daną powierzchnię. Montowany np. w podłodze lub w oknach (przykład: Mission Impossible).
### Microwave
- Podczerwień dobrze sprawdza się w ograniczonych obszarach, ale przy większej powierzchni lepiej sprawdzają się czujniki. Zasada działania opiera się na częstotliwości mikrofal - w celu wykrycia ruchu emitowane są impulsy mikrofal (microwave pulses), a następnie sprawdzane jest odbicie od poruszającego się obiektu.
### Ultrasonic
- Czujnik ultradźwiękowy. Wysyła sygnały ultradźwiękowe i sprawdza, czy te fale dźwiękowe odbijają się od obiektów (podobnie jak nietoperze). Taki czujnik może być wykorzystany nie tylko do wykrywania ruchu, ale również do wykrywania ewentualnych kolizji. 
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
- [Centraleyes: What is a Gap Analysis?](https://www.centraleyes.com/glossary/security-gap-analysis/)
- [CloudFlare: Zero Trust security | What is a Zero Trust network?](https://www.cloudflare.com/learning/security/glossary/what-is-zero-trust/)
- [CloudFlare: What is the control plane? | Control plane vs. data plane](https://www.cloudflare.com/learning/network-layer/what-is-the-control-plane/)
- [CertBros: Zero Trust Explained | Real World Example](https://www.youtube.com/watch?v=Y3DjoTiOiOU&ab_channel=CertBros)
- [Check Point: Network Segmentation vs Micro-Segmentation](https://www.checkpoint.com/cyber-hub/network-security/network-segmentation-vs-micro-segmentation/)