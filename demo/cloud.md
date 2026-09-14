

On-premises - tym terminem określa się infrastrukturę IT (sprzęt, oprogramowanie, dane itp.), która jest pod pełną kontrolą danej organizacji. Inne określenia, z którymi można się spotkać to on-site oraz in-house. Kiedy je usłyszymy w kontekście firmy to możemy śmiało założyć, że chodzi o zasoby, które są w pełni kontrolowane/rozwijane przez daną firmę. Jeśli przyjrzymy się jak wygląda przykład standardowej infrastruktury IT (przedstawiony poniżej), przekonamy się, że jest to dosyć szeroki zakres odpowiedzialności.

Cloud - czyli rozwiązania chmurowe lub po prostu chmura. Nie chcę teraz wchodzić w szczegółowe definicje czym chmura jest, a czym nie jest (oczywiście w kontekście rozwiązań IT, a nie meteorologii :)), ale tym mianem możemy określić sieć serwerów zdalnych, które są połączone w jeden ekosystem i pełnią różne funkcje, takie jak przechowywanie danych z możliwością zdalnego zarządzania czy też udostępnianie różnych aplikacji i usług wirtualnych (np. poczta elektroniczna). Niewątpliwą zaletą chmury jest zdalny dostęp do zasobów z niemalże każdego miejsca.

Weźmy łopatologiczny przykład: zamiast trzymać zdjęcia z podróży życia na swoim osobistym komputerze, możesz je wrzucić np. na Dysk Google (Google Drive) i mieć do nich dostęp z wielu urządzeń (np. smartfon). Gdyby dysk na Twoim komputerze został nieodwracalnie zniszczony, Twoje zdjęcia zostaną ocalone, ponieważ są przechowywane w chmurze (w tym konkretnym przykładzie na wirtualnym dysku Google).

Rozwiązania chmurowe stają się coraz popularniejsze i już od dłuższego czasu można zaobserwować tendencję przenoszenia zasobów do chmury przez poszczególne organizacje. Nasuwa się pytanie: czy jest to rozwiązanie bezpieczne w porównaniu do trzymania danych u siebie?

Często można spotkać się z dwoma skrajnymi podejściami. Jedno opiera się na założeniu, że chmura to jest przyszłość i prędzej czy później będzie jedynym słusznym modelem zarządzania infrastrukturą IT, który jest w 100% bezpieczny. Drugie podejście zakłada, że dane są najbezpieczniejsze tylko wtedy, gdy mamy nad nimi pełną kontrolę i żaden dostawca usług chmurowych (CSP = Cloud Service Provider) nie ma do nich wglądu.

Jak to zwykle bywa, prawda leży po środku. Nie ma jednoznacznej odpowiedzi na pytanie, która opcja jest lepsza/bezpieczniejsza, ponieważ to wszystko zależy od naszych potrzeb i priorytetów. W tym opracowaniu przyjrzymy się wadom i zaletom obydwu rozwiązań. Jednak zanim przejdziemy do meritum, przyjrzyjmy się podstawowym pojęciom związanym z utrzymywaniem infrastruktury IT w chmurze.
Przykład standardowej infrastruktury IT

Zacznijmy od krótkiego wglądu w to, jak może wyglądać standardowa infrastruktura IT w większości organizacji, składająca się z różnych warstw (obszarów odpowiedzialności), zaczynając od warstwy najniższego poziomu:

    Storage - krótko mówiąc, chodzi o magazynowanie danych. Ta warstwa obejmuje sprzęt (serwery, dyski itp.) przeznaczony do składowania wszystkich danych organizacji oraz miejsce, w którym ten sprzęt będzie się znajdował.
    Networking - czyli zaprojektowanie, zbudowanie oraz utrzymywanie sieci, która zapewnia dostęp do danych oraz komunikację pomiędzy poszczególnymi elementami danej organizacji (np. stacje robocze pracowników połączone w lokalną sieć, z dostępem do określonych usług, a także do Internetu).
    Servers - konfiguracja oraz utrzymanie serwerów (sprzętu), na których przechowywane są dane, a także są hostowane usługi oraz oprogramowanie wykorzystywane przez daną organizację.
    Virtualization - w dosłownym tłumaczeniu jest to wirtualizacja. W większości przypadków serwery sprzętowe są maszynami o dużej mocy obliczeniowej, więc można je wykorzystać do utworzenia wielu odizolowanych od siebie środowisk w postaci maszyn wirtualnych (ang. virtual machines). Dzięki temu, pomimo że fizycznie posiadamy jeden serwer, mamy do dyspozycji kilka niezależnych od siebie serwerów wirtualnych (oczywiście ich dostępne zasoby stanowią tylko część mocy obliczeniowej maszyny fizycznej).
    Operating systems - chodzi oczywiście o systemy operacyjne (OS), takie jak Windows czy Linux. Żeby sprzęt spełniał swoją funkcję musi być na nim zainstalowany odpowiedni system operacyjny. Oczywiście dotyczy to również maszyn wirtualnych. Do tego dochodzi konfiguracja, dbanie o aktualizacje, a także zakup i odnawianie licencji wymaganych przez poszczególne systemy.
    Middleware - w dosłownym tłumaczeniu jest to oprogramowanie pośredniczące. Pod tą nazwą kryje się rodzaj oprogramowania umożliwiający komunikację pomiędzy różnymi aplikacjami, usługami bądź systemami. Celem middleware jest utworzenie swego rodzaje pomostu pomiędzy różnymi technologiami w taki sposób, żeby mogły one działać jak jeden spójny system. Przykładem może być kolejka komunikatów (ang. message queue), która umożliwia komunikację między dwoma niezależnymi procesami/aplikacjami za pośrednictwem wiadomości przesyłanych odpowiednio zdefiniowanym protokołem (np. RabbitMQ lub wbudowany w Windows MSMQ).
    Runtime - środowisko uruchomieniowe, czyli platforma, na której działają aplikacje i usługi wysokiego poziomu (tj. oprogramowanie, z którego korzystają użytkownicy). Może to być platforma .NET, maszyna wirtualna języka Java (JVM), a w przypadku aplikacji webowych serwer HTTP (np. IIS będący częścią systemu Windows). Do tej kategorii można również zaliczyć kontenery Docker.
    Applications & Data - aplikacje i dane, czyli warstwa najwyższego poziomu, z której bezpośrednio korzystają użytkownicy, zarówno wewnętrzni (np. pracownicy firmy), jak i zewnętrzni (np. klienci firmy). Może to być na przykład sklep internetowy, za pośrednictwem którego firma sprzedaje swoje produkty. Taki sklep zazwyczaj składa się m.in. z aplikacji webowej, do której użytkownicy mają dostęp za pośrednictwem przeglądarki internetowej oraz bazy danych, w której przechowywane są wszystkie informacje niezbędne do działania sklepu (dane o produktach, użytkownikach itp.).

Rodzaje usług chmurowych

Aktualnie możemy wyróżnić 4 rodzaje usług chmurowych ze względu na poziom dostępności:

    Chmura publiczna (ang. public cloud) - usługi chmurowe są dostępne publicznie za pośrednictwem Internetu, dzięki czemu każdy, kto wykupi odpowiednią subskrypcję ma do nich dostęp. W tym modelu zasoby są współużytkowane przez innych klientów (oczywiście w odpowiednio wyizolowanych środowiskach). Na przykład: Microsoft Azure, Amazon Web Services (AWS), Google Cloud czy chociażby wspomniana wcześniej usługa Google Drive.
    Chmura prywatna (ang. private cloud) - w tym przypadku zasoby nie są współdzielone i dostęp do nich mają tylko członkowie danej organizacji w ramach prywatnej sieci. Infrastruktura może fizycznie znajdować się w centrum danych należącym do organizacji, ale może też być utrzymywana przez zewnętrzną firmę hostingową. Jednak cechą charakterystyczną jest fakt, że jest ona dedykowana wyłącznie dla danej organizacji, a dostęp do niej jest możliwy jedynie przez sieć prywatną. W gruncie rzeczy ten model jest bardzo podobny do omawianego wcześniej modelu on-premises.
    Chmura hybrydowa (ang. hybrid cloud) - połączenie modelu chmury publicznej z chmurą prywatną, tj. część usług/zasobów działa w chmurze publicznej, a część w chmurze prywatnej. Jest to przeważnie najkorzystniejszy model, z którego korzysta bardzo wiele firm. Bardzo często dostawcy usług chmurowych (CSP) umożliwiają wygodne połączenie obu środowisk.
    Chmura społecznościowa/współdzielona (ang. community cloud) - czasami organizacje nie chcą korzystać z usług chmury publicznej (np. ze względu na restrykcyjne przepisy dotyczące przechowywania wrażliwych danych), ale nie stać ich też na utrzymanie chmury prywatnej czy zarządzanie całą infrastrukturą we własnym zakresie. W takim przypadku organizacje, które mają wspólne cele i wartości mogą stworzyć współdzieloną chmurę, do której mają dostęp jedynie członkowie zrzeszonych organizacji. Przykładem takiej komitywy mogą być instytucje rządowe.

Załóżmy, że zdecydowaliśmy się skorzystać z usług oferowanych przez firmę trzecią (CSP). Czy to znaczy, że po prostu dajemy kluczyk do naszej serwerowni dostawcy i już o nic nie musimy się martwić? Niestety, tak to nie działa.

Korzystając z usług chmurowych musimy być świadomi, że odpowiedzialność za utrzymanie i bezpieczeństwo infrastruktury IT leży po obu stronach - dostawcy oraz naszej. Jednakże zakres tej odpowiedzialności może się różnić w zależności od wybranego modelu (ang. cloud service models). Przyjrzyjmy się więc tym najpopularniejszym.
Infrastructure as a Service (IaaS)

Ten model jest najbliższy do utrzymywania własnej infrastruktury IT (on-premises). Dostawca dostarcza jedynie bazową infrastrukturę w postaci serwerów połączonych w sieć oraz podstawowe oprogramowanie zapewniające wirtualizację.

Oczywiście taka infrastruktura znajduje się w centrach danych (ang. data centers) należących do dostawcy CSP (Cloud Service Provider), który dba również o zasilanie, okablowanie, utrzymanie odpowiedniej temperatury, a także zapewnienie fizycznej ochrony. Za wszystko inne, wliczając w to instalację systemów operacyjnych (OS), odpowiadamy już my sami. W związku z tym możemy się jeszcze spotkać z określeniem Hardware as a Service (HaaS).

Warto zaznaczyć, że w tym modelu klienci zazwyczaj mają do dyspozycji dedykowane wirtualne środowiska, więc jeśli stwierdzimy, że potrzebujemy dodatkowego serwera, to utworzenie nowej maszyny wirtualnej (VM) jest zdecydowanie szybsze niż przygotowanie fizycznego serwera. Oczywiście to my będziemy musieli zainstalować na tej maszynie odpowiedni OS.
Platform as a Service (PaaS)

Myślę, że ten model można swobodnie nazwać zarządzanym środowiskiem hostingowym. CSP odpowiada już nie tylko za sprzęt, sieć i wirtualizację, ale także za utrzymanie systemów operacyjnych oraz przeważnie za oprogramowanie niezbędne do uruchomienia naszych aplikacji, czyli wspomniane wcześniej warstwy middleware oraz runtime.

Doskonałym przykładem mogą być różnego rodzaju firmy oferujące hosting webowy - my musimy jedynie napisać aplikację w wybranej technologii (np. PHP; ASP.NET; Django), a usługodawca zapewnia środowisko niezbędne do jej uruchomienia tj. OS (np. Windows/Linux), platformę uruchomieniową (np. interpretery języków skryptowych; .NET Core), a także bazy danych i odpowiednie serwery HTTP.

Oczywiście nie obejdzie się bez podstawowej konfiguracji tego środowiska, ale zazwyczaj jest to proces uproszczony za sprawą webowego interfejsu użytkownika. Innym przykładem może być usługa Azure App Service, gdzie możemy sobie wyklikać odpowiednie środowisko dostosowane do naszej aplikacji.

Ten model jest również dużym wyzwaniem pod względem bezpieczeństwa, ponieważ zakres odpowiedzialności jest rozmyty pomiędzy dostawcą usług, a klientem. Co prawda za OS odpowiada usługodawca, ale usługobiorca może w niektórych przypadkach mieć możliwość bezpośredniego zalogowania się do systemu (z ograniczonymi uprawnieniami) i/lub zmiany domyślnych ustawień. Żeby uniknąć nieporozumień należy dobrze zapoznać się z dokumentacją oraz warunkami korzystania z usług chmurowych.
Software as a Service (SaaS)

W tym modelu niemalże całe zarządzanie spoczywa w rękach CSP. My jedynie korzystamy z udostępnionego oprogramowania, które pełni użyteczną dla nas funkcję. Na przykład: poczta elektroniczna Gmail; system do zarządzania fakturami InFakt czy rozbudowana platforma biznesowo-biurowa Microsoft 365 (dawniej Office 365).

Wystarczy, że zalogujemy się do usługi przez przeglądarkę (lub inne dedykowane oprogramowanie klienckie) i mamy wrażanie, że używamy aplikacji zainstalowanej bezpośrednio na naszym komputerze.

Pamiętajmy jednak, że pomimo dużego zakresu odpowiedzialności po stronie dostawcy, my również w pewnym stopniu odpowiadamy za bezpieczeństwo usługi. W wielu przypadkach to my będziemy tworzyć konta użytkowników i nadawać im stosowne uprawnienia. Do tego dochodzi ewentualne zabezpieczenie systemów klienckich, czyli urządzeń, które będą wykorzystane do połączenia z daną usługą.

Ten model nie uchroni nas również przed pomyłkami użytkowników, takimi jak przypadkowe usunięcie danych czy omyłkowe udostępnienie danych dostępowych osobom niepożądanym (np. za sprawą phishingu).
Anything as a Service (XaaS)

Powyżej omówiliśmy sobie 3 główne modele usług chmurowych. Oczywiście nie są to sztywne ramy, ponieważ istnieją jeszcze różne odmiany, które trudno jednoznacznie sklasyfikować. Często określa się je jako Anything as a Service (XaaS).

Do tej grupy możemy zaliczyć m.in. Database as a Service (DBaaS), czyli dostęp do platformy bazodanowej, czy też Function as a Service (FaaS) polegający na możliwości uruchomienia kawałka kodu spełniającego określoną funkcję bez konieczności tworzenia całej aplikacji (inne określenie tego modelu to Serverless).

Warto jeszcze tutaj wspomnieć o modelu, który zyskuje ostatnio na popularności i opiera się na świadczeniu usług z zakresu szeroko pojętego bezpieczeństwa: Security as a Service (SECaaS).
Macierz odpowiedzialności

Podsumujmy to co już wiemy w formie tabelki przedstawiającej tzw. macierz odpowiedzialności, czyli kto jest za co odpowiedzialny w różnych modelach.

Dla przypomnienia: Firma - organizacja, która potrzebuje infrastruktury IT do funkcjonowania; CSP - dostawca usług chmurowych.
Macierz odpowiedzialności
Porównanie rozwiązań

Skoro orientujemy się już z jakimi problemami musi mierzyć się organizacja, która buduje własną infrastrukturę IT, oraz zapoznaliśmy się z popularnymi modelami rozwiązań chmurowych, nadszedł czas na porównanie obydwu opcji.

Jak wspomniałem wcześniej, nie ma jednoznacznej odpowiedzi na to, które rozwiązanie jest lepsze/bezpieczniejsze, ponieważ wszystko zależy od naszych potrzeb i priorytetów. Atakującego guzik obchodzi gdzie trzymamy nasze dane, więc zarówno tu i tu trzeba zadbać o ich bezpieczeństwo. Różnią się jedynie obszarami, nad którymi powinniśmy się skupić.

Poniżej znajduje się krótka charakterystyka rozwiązań chmurowych oraz podejścia on-premises w kontekście różnych obszarów. Na jej podstawie powinniśmy być w stanie wybrać to, które jest najlepiej dopasowane do naszych potrzeb. Miej tylko proszę na uwadze, że poniższe rozważania dotyczą w większości przypadków modeli usług chmurowych, które są odpowiednikiem zarządzania infrastrukturą on-premises, czyli głównie IaaS (Infrastrukture as a Service) oraz ewentualnie PaaS (Platform as a Service).
Wygoda użytkowania

Jeśli chodzi o wygodę użytkowania to myślę, że chmura (cloud) jest tutaj faworytem. Nie musimy się bowiem martwić o sprzęt, oprogramowanie czy zarządzenie własnym centrum danych. O to wszystko dba dostawca usług chmurowych (CSP = Cloud Service/Solution Provider). Nawet w modelu IaaS (Infrastructure as a Service) mamy zapewniony hardware wraz z niskopoziomowym oprogramowaniem umożliwiającym wirtualizację.

Zarządzanie infrastrukturą w chmurze jest w większości przypadków stosunkowo przyjemne za sprawą przyjaznych użytkownikom interfejsów webowych. Kiedy potrzebujemy nowego serwera, nie musimy jechać do naszego centrum danych z nowym sprzętem oraz instalować na miejscu oprogramowania, ponieważ całe zarządzanie odbywa się zdalnie - wystarczy kilka kliknięć i po paru minutach mamy w pełni skonfigurowany serwer gotowy do działania. Ma to szczególne znaczenie, jeśli zespół w naszej organizacji jest rozproszony i pracuje zdalnie.

Z drugiej strony, możliwości konfiguracyjne infrastruktury IT udostępnione przez CSP mogą być ograniczone i w niektórych przypadkach niewystarczające. Kiedy budujemy infrastrukturę on-premises możemy wszystko skonfigurować dokładnie tak jak chcemy, bez żadnych ograniczeń, ale kosztem czasu jaki musimy na to poświęcić.
Prywatność i poufność danych

Jedną z największych obaw dotyczących przechowywania danych w chmurze jest prywatność i poufność danych (ang. data privacy/confidentiality). Czasami dostęp osób trzecich, włączając w to CSP, może stanowić problem dla organizacji. Oprócz ochrony swoich danych, które stanowią tajemnicę biznesową i często decydują o konkurencyjności firmy, pozostaje jeszcze kwestia danych wrażliwych, których przetwarzanie jest uregulowane prawnie. Do tej grupy możemy zaliczyć m.in. dane medyczne, dane bankowe czy te przetwarzane przez instytucje rządowe.

W przypadku trzymania danych u siebie (on-premises), to my mamy nad nimi pełną kontrolę. Decydujemy o tym w jaki sposób są zbierane, przechowywane i przetwarzane oraz kto ma do nich dostęp. Czy takie podejście jest najbezpieczniejsze to kwestia dyskusyjna, ale na pewno zapewnia 100% prywatności (przynajmniej z założenia). Pamiętajmy jednak, że jeśli zdarzy się wypadek w postaci kradzieży czy wycieku danych to my ponosimy za to pełną odpowiedzialność.

W rozwiązaniach chmurowych (cloud), nie mamy fizycznego dostępu do naszych danych, co sprawia, że nie musimy się martwić o fizyczne zabezpieczenia - o to dba już CSP. Problemem dla niektórych może być jednak dostęp podmiotów trzecich, o których tak naprawdę nic nie wiemy i nie mamy nad nimi żadnej kontroli (CSP też może zatrudniać różnych podwykonawców). Jeśli nie chcemy, żeby osoby trzecie miały wgląd w nasze dane, możemy je zaszyfrować przed umieszczeniem ich w chmurze. Chociaż oczywiście wiąże się to z dodatkowymi utrudnieniami, a przy niektórych usługach może okazać się wręcz niemożliwe.

Czy jest to jednak duży problem? Patrząc na sprawę obiektywnie, raczej nie. Solidni dostawcy usług chmurowych dbają o to, żeby nikt poza stronami umowy (i ewentualnie CIA/NSA/FBI ;)) nie miał dostępu do Twoich danych.

Utrudnieniem mogą wydawać się przepisy, które narzucają restrykcyjne standardy obchodzenia się z poufnymi danymi (np. rozporządzenie GDPR dotyczące przetwarzania danych osobowych obywateli EU), ale wielu CSP oferuje usługi, które są w pełni zgodne z obowiązującymi przepisami. Skrajnym przykładem może być Microsoft Azure, który oferuje specjalne usługi dla instytucji rządowych czy też odseparowane od reszty zasoby będące pod kontrolą chińskiego operatora 21Vianet (chińskie prawo zabrania oferowania usług chmurowych zagranicznym podmiotom, więc Microsoft dogadał się z miejscowym operatorem).

Uwaga, ten akapit jest wyłącznie moją opinią. Pozostaje jeszcze kwestia ideowa. Zauważam niepokojący trend stopniowego rezygnowania ze swojej prywatności na rzecz wygody i pozornego bezpieczeństwa. O ile nie stanowi to aktualnie poważnego problemu (i oby tak zostało), to czuję pewne obawy obserwując coraz większy wpływ technologii na nasze życie i autorytarne zapędy rządów oraz dużych korporacji. Coraz doskonalsze algorytmy sztucznej inteligencji w połączeniu z ogromną ilością danych, które sami dobrowolnie udostępniamy mogą spowodować, że któregoś dnia obudzimy się w złotej klatce. Pozostawiam do rozważenia słowa Benjamina Franklina: Gdy dla tymczasowego bezpieczeństwa zrezygnujemy z podstawowych wolności, nie będziemy mieli ani jednego, ani drugiego.
Zgodność z obowiązującymi przepisami

Kwestia zgodności z obowiązującymi przepisami (ang. legal compliance) została już poruszona w powyższym paragrafie. Organizacje decydujące się na budowanie własnej infrastruktury IT lub na rozwiązania chmurowe muszą upewnić się, że spełniają wszystkie wymogi prawne dotyczące danych.

Przykładem takich regulacji jest wspomniane wcześniej rozporządzenie GDPR (General Data Protection Regulation) obowiązujące w Europie (w Polsce znane jako RODO), czy też ustawa HIPAA (Health Insurance Portability Act), która określa wymogi jakie muszą spełniać wszystkie podmioty przetwarzające informacje związane ze zdrowiem (np. ubezpieczyciele) w Stanach Zjednoczonych. Za złamanie wspomnianych regulacji grożą gigantyczne kary pieniężne, więc obawa przed doborem niewłaściwych rozwiązań jest jak najbardziej uzasadniona.

Kiedy trzymamy wszystko u siebie (on-premises), oczywistym jest, że to my w pełni odpowiadamy za przystosowanie całego naszego zaplecza do obowiązujących przepisów. Z jednej strony mamy nad tym pełną kontrolę i teoretycznie jesteśmy w stanie spełnić wszystkie wymagania co do joty, ale z drugiej strony dostosowanie już działającej infrastruktury, choć w wielu przypadkach wiąże się tylko ze zmianami w oprogramowaniu, może być czasochłonne i drogie.

Alternatywą jest chmura (cloud). Oczywiście musimy się najpierw upewnić, że wybrany przez nas CSP oferuje usługi, które są zgodne z obowiązującym prawem. Więksi gracze (np. Microsoft Azure, AWS, Google Cloud) posiadają już w swojej ofercie takie usługi, a ich kolejną zaletą jest fakt, że w razie jakichkolwiek zmian w przepisach mają środki, żeby szybko przystosować swoją infrastrukturę do nowych aktów prawnych.

Pozostaje jeszcze kwestia suwerenności danych (ang. data sovereignty), czyli zagadnienia związanego z ich geograficznym umiejscowieniem. Duzi dostawcy usług chmurowych mają centra danych rozrzucane po całym świecie. Jest to spowodowane wieloma czynnikami, ale główne z nich to możliwość składowania danych blisko ich użytkowników, co skraca czas potrzebny na transfer informacji, oraz redundancja, która zapewnia ciągłość działania nawet kiedy jedno z centrów danych przestanie funkcjonować (np. z powodu katastrofy naturalnej).

Problem pojawia się w chwili gdy przepisy wymuszają przechowywanie danych w konkretnym miejscu (np. GDPR nakazuje, żeby dane użytkowników z UE były przechowywane w granicach Unii Europejskiej). Chociaż to również nie stanowi przeszkody dla popularnych usługodawców - np. Azure pozwala na wybranie regionu, w którym będą składowane nasze dane wraz z hostowanymi usługami.
Niezawodność

Niezawodność (ang. reliability), czyli stopień w jakim można polegać na infrastrukturze IT, da się zmierzyć za pomocą dwóch czynników:

    Dostępność (ang. availability) - czy możemy w każdej chwili i bez problemu uzyskać stosunkowo szybki dostęp do naszych zasobów?
    Czas nieprzerwanego działania (ang. uptime) - jak długo nasze usługi działają prawidłowo bez żadnych przerw? Przeciwieństwem tej metryki jest czas przestoju w działaniu (ang. downtime).

Standardowo, przy samodzielnym zarządzaniu zasobami on-premises to wszystko zależy od nas. Żeby zapewnić wysoki poziom niezawodności należy zadbać o redundancję (nadmiarowe zasoby, które mogą zostać szybko wykorzystane w razie awarii podstawowej infrastruktury) oraz częste i regularne tworzenie kopii zapasowych. Do tego dochodzi posiadanie kompetentnego zespołu IT, który potrafi szybko i sprawnie reagować na różne incydenty.

To wszystko wiąże się niestety z ogromnymi kosztami. Jedynie bardzo dobrze prosperujące organizacje mogą sobie pozwolić na posiadanie lustrzanej kopii podstawowej serwerowni, która jest w pełnej gotowości do działania w razie awarii tej pierwszej. W przeciwnym razie odbudowa w pełni funkcjonalnego środowiska może zająć sporo czasu, w którym firma będzie ponosiła straty.

Inną równie ważną kwestią jest transfer danych, zarówno pod kątem przepustowości (ang. bandwidth), jak i opóźnień wynikających z działania sieci (ang. network latency). Do szybkiego przesyłania informacji są potrzebne dobrej jakości łącza o dużej przepustowości. Znaczenie ma również miejsce, do którego chcemy wysyłać dane. Jeśli nasze serwery znajdują się w Polsce, a użytkownikami są obywatele Brazylii, to narzut czasowy związany z koniecznością transferu danych do tak oddalonego miejsca może znacząco obniżyć jakość świadczonych przez nas usług.

W przypadku skorzystania z rozwiązań chmurowych sytuacja wygląda nieco prościej. Zaletą korzystania z usług dużych dostawców jest posiadanie przez nich wielu centrów danych na całym świecie. Dzięki temu są w stanie zapewnić szybki i niezawodny dostęp do danych nam oraz naszym klientom. Przykładowo, Azure zapewnia dostępność do swoich usług przez co najmniej 99% czasu (niektóre usługi maja zapewnione nawet 99,9%). Jest to możliwe, ponieważ ogromne zasoby należące do CSP pozwalają na redundancję danych.

Korzystając z chmury możemy często wybrać centrum danych, które znajduje się najbliżej naszych odbiorców, przez co znacznie skracamy czas transferu informacji, ale także obniżamy koszty jakie musimy ponieść za usługę świadczoną przez CSP (w rozwiązaniach chmurowych bardzo często płaci się jedynie za wykorzystane zasoby). Dodatkowo, jest bardzo prawdopodobne, że za te wszystkie benefity zapłacimy mniej niż w przypadku podobnej konfiguracji on-premises. Wiąże się to z tzw. korzyścią skali, o której powiemy sobie w sekcji związanej z kosztami.
Skalowanie

Skalowanie (ang. scalability), czyli zdolność do relatywnie szybkiego zwiększenia/zmniejszania zasobów celem zaspokojenia rosnących/malejących potrzeb i wymagań względem infrastruktury IT. Z tym pojęciem wiążą się jeszcze dwa zbliżone do siebie zagadnienia:

    Zwinność (ang. agility) - determinuje jak szybko jesteśmy w stanie zmodyfikować naszą infrastrukturę w razie wystąpienia potrzeby. Innymi słowy, zdolność do szybkiego skalowania.
    Elastyczność (ang. elasticity) - zdolność do dynamicznego skalowania. Określa czy jesteśmy w stanie skalować zasoby w sposób automatyczny w razie wystąpienia określonych okoliczności (np. automatyczne uruchomienie się dodatkowej instancji aplikacji webowej na drugim serwerze, żeby obsłużyć zwiększony ruch sieciowy).

Podejście on-premises jest pod tym względem trochę mniej elastyczne. Kiedy stwierdzimy, że nasza infrastruktura wymaga zmiany bądź modernizacji (włączając to zmiany związane z bezpieczeństwem) to przeważnie wymaga czasu, ponieważ często w takich wypadkach trzeba zakupić nowy sprzęt i/lub oprogramowanie, a następnie to wszystko skonfigurować.

Jeśli chcemy uzyskać wysoki poziom zwinności i elastyczności (krótko omówionych powyżej) musielibyśmy mieć odpowiednio przygotowane środowisko z zapasowymi zasobami, gotowymi w każdej chwili do działania. Takie podejście generuje jednak duże koszty, które musielibyśmy ponieść z góry, bez pewności czy rzeczywiście się zwrócą w przyszłości.

Również w tym obszarze chmura wydaje się być korzystniejszym rozwiązaniem. Wprowadzanie zmian i rozbudowa naszej wirtualnej infrastruktury często sprowadza się do kilku kliknięć w interfejsie udostępnionym przez CSP (np. w ciągu kilku minut jesteśmy w stanie postawić i uruchomić wstępnie skonfigurowanego firewalla sieciowego).

Możemy także skonfigurować tzw. progi (ang. thresholds), po przekroczeniu których wymagane zasoby są dodawane lub odejmowane automatycznie. Jest to istotna cecha, ponieważ w rozwiązaniach chmurowych, jak zostało już wcześniej wspomniane, płacimy przeważnie tylko za to co rzeczywiście wykorzystujemy. Jeśli na przykład okaże się, że nie potrzebujemy już dodatkowej przestrzeni dyskowej, to chcielibyśmy z niej jak najszybciej zrezygnować, żeby nie generowała dodatkowych kosztów.

Miejmy na uwadze, że dostawcy usług chmurowych to nie są organizacje charytatywne i wbrew pozorom ich usługi wcale nie są szczególnie tanie - nawet w modelu płatności opartym tylko o zużyte zasoby (consumption-based). Dlatego chmura jest dobrym wyborem w przypadku bardzo szybko rosnących biznesów, które wymagają dużej skalowalności. W przypadku mniejszych przedsięwzięć o stabilnym i przewidywalnym wzroście, może okazać się, że postawienie i utrzymanie infrastruktury on-premises jest korzystniejsze (określona kwota zapłacona z góry, która wystarczy na kilka lat).
Zespół IT

Nie jest niespodzianką, że do utrzymania kontroli nad złożoną infrastrukturą IT (on-premises) potrzebny jest zespół kompetentnych specjalistów, którzy będą w stanie odpowiednio zabezpieczyć dane organizacji. Dodatkowo, taki zespół musi zadbać o ciągłość działania całej infrastruktury (uptime) oraz zapewnić nieprzerwany dostęp do danych (availability). Jeśli tego zabraknie, biznes może bardzo szybko upaść. To wszystko wiąże się oczywiście z niemałymi kosztami.

Bądźmy jednak świadomi tego, że korzystanie z rozwiązań chmurowych nie oznacza, że nie potrzebujemy w ogóle zespołu IT, jak to często jest przedstawiane w różnych materiałach marketingowych. O ile w przypadku usług typu SaaS (Software as a Service) rzeczywiście może okazać się, że nie potrzebujemy specjalistów do ich obsługi, to przy pozostałych modelach (PaaS; IaaS) dobrze mieć u boku inżyniera, który zna daną platformę (choć faktycznie, taki zespół jest przeważnie mniejszy niż w przypadku podejścia on-premises).

Dlatego też często można spotkać oferty pracy dla specjalistów od rozwiązań chmurowych, takich jak Azure, AWS czy Google Cloud. Pamiętajmy, że nieumiejętne budowanie infrastruktury w chmurze również może nas bardzo drogo kosztować.

Istotną kwestią w wielu firmach jest reagowanie na incydenty (ang. incident response) - czy to związane z naruszeniem bezpieczeństwa (np. potencjalny atak), czy zwykłe awarie typu: serwer nie odpowiada. Zaletą posiadania zespołu IT po swojej stronie jest fakt, że nie musisz polegać na zewnętrznych usługodawcach, których czas reakcji na różne incydenty może być dłuższy niż Twoje oczekiwania. Dodatkowo, może pojawić się problem z rozmytą odpowiedzialnością w przypadku usług chmurowych, dlatego ważne jest ustalenie, kto i w jakim zakresie odpowiada za poszczególne elementy całego systemu.

Na koniec warto jeszcze wspomnieć, że chmura jest dobrą opcją, jeśli Twój zespół jest rozproszony i pracuje zdalnie.
Koszty

O temat kosztów zdążyliśmy już niejednokrotnie zahaczyć przy okazji omawiania pozostałych obszarów, więc teraz zrobimy sobie krótkie podsumowanie. Na początek należy sobie uświadomić, że nie ma uniwersalnej odpowiedzi na pytanie: które podejście jest tańsze (chmura czy on-premises), bo to wszystko zależy od wielu czynników.

Wszelkie wydatki na infrastrukturę on-premises ponosimy przeważnie z góry (ang. upfront), czyli najpierw musimy wyłożyć kasę na sprzęt, oprogramowanie i zespół, żeby w ogóle ruszyć z biznesem. Jeśli musimy rozbudować nasze zaplecze IT, to ponosimy kolejne koszty i to często nadmiarowe. Przykładowo, jeśli potrzebujemy zwiększyć moc obliczeniową naszego serwera tylko na pewien okres, to i tak zapłacimy pełną cenę za dodatkowy sprzęt w nadziei, że jeszcze kiedyś się przyda. Do tego wszystkiego dochodzą koszty związane z utrzymaniem (prąd, chłodzenie, naprawy itp.), które również spoczywają na naszych barkach.

W rozwiązaniach chmurowych bardzo często występuje tzw. efekt korzyści skali (ang. economies of scale), polegający na tym, że firmy, które osiągają ogromne rozmiary potrafią skutecznie zmniejszyć swoje całkowite koszty. Giganci usług chmurowych (Microsoft, Amazon, Google), którzy posiadają olbrzymią liczbę klientów, są w stanie sprzedawać dostęp do swoich niemalże nieograniczonych zasobów po akceptowalnych cenach.

Kolejną zaletą chmury jest model płatności polegający na płaceniu tylko za zasoby, które rzeczywiście wykorzystaliśmy (ang. consumption-based model). Czyli nie ponosimy żadnych kosztów z góry i jeśli już czegoś nie potrzebujemy to możemy z tego zrezygnować, bez ponoszenia kolejnych kosztów. Pamiętajmy jednak, że jeśli korzystamy z chmury nieumiejętnie, to również możemy wygenerować niebotyczne rachunki, o czym przeczytamy w artykule z Niebezpiecznika: Ile kosztuje niewiedza w chmurze? Analiza 5 niepotrzebnie wysokich rachunków.

Podsumowując, infrastruktura on-premises może okazać się rozsądnym wyborem kiedy prowadzimy nieduży biznes, dla którego przewidujemy stabilny wzrost w stosunkowo długiej perspektywie. Wtedy może się okazać, że wszelkie koszty poniesione z góry i tak będą tańszą opcją niż subskrypcja na usługi chmurowe. Jeśli zaś chodzi o większe organizacje charakteryzujące się bardzo dynamicznym wzrostem, to chmura może być korzystniejszym rozwiązaniem.
Bezpieczeństwo

W tej sekcji skupimy się głównie na kwestiach bezpieczeństwa rozwiązań chmurowych, ponieważ w przypadku infrastruktury on-premises sprawa jest raczej oczywista - to Ty masz całkowitą kontrolę, więc jak się zabezpieczysz, tak się wyśpisz ;).
With great power comes great responsibility

Jak więc wygląda sytuacja kiedy korzystamy z usług CSP (Cloud Service/Solution Provider)? Zacznijmy od zakresu odpowiedzialności i od przypomnienia, że ostatecznie to i tak my odpowiadamy za bezpieczeństwo naszych danych. Jednakże migrując zasoby do chmury możemy pozbyć się dużej części tej odpowiedzialności (oczywiście za cenę stuprocentowej prywatności i swobody konfiguracji). Jak duża to będzie część zależy od umowy z dostawcą oraz od wybranego modelu usługi, ale generalne zasady zostały bardzo fajnie przedstawione na grafice dostępnej w serwisie kapitanhack.pl: Model współdzielonej odpowiedzialności w chmurach publicznych.

Niezależnie od wybranego rodzaju usług chmurowych, zarządzanie tożsamością użytkowników (identyfikacja, uwierzytelnienie i autoryzacja) oraz zabezpieczenie urządzeń klienckich zawsze leży po stronie usługobiorcy. Jest to szczególnie ważne zagadnienie, ponieważ wiele elementów chmury jest ze sobą ściśle powiązanych i przejęcie bądź utrata danych uwierzytelniających przez któregokolwiek z użytkowników może doprowadzić do kompromitacji wielu obszarów jednocześnie.

Dlatego tak istotne jest upewnienie się, że użytkownicy chmury zawsze używają odpowiednich procesów i przestrzegają wytycznych, kiedy próbują uzyskać dostęp do pożądanych zasobów. CSP może stawać na rzęsach, żeby odpowiednio zabezpieczyć wrażliwe dane organizacji, ale jeśli jej użytkownicy przez przypadek opublikują gdzieś link do bazy danych wraz z informacjami uwierzytelniającymi, to cały wysiłek usługodawcy idzie na marne.
Disappointed CSP

Jeśli chodzi o bezpieczeństwo danych to chmura ma pewną przewagę nad prywatną infrastrukturą (on-premises), wynikającą z następujących okoliczności:

    CSP posiadają wiele nieustannie monitorowanych centrów danych, rozproszonych geograficznie, dzięki czemu są w stanie zapewnić niemalże 100% ochronę przed zagrożeniami fizycznymi (włamanie do centrum danych; katastrofy naturalne).
    Duzi usługodawcy mogą pozwolić sobie na zatrudnienie ludzi, którzy zajmują się TYLKO dbaniem o bezpieczeństwo przechowywanych danych, przez co nie są rozpraszani przez inne zadania (jak to często bywa w mniejszych zespołach IT).
    Ze względu na skalę działalności, CSP mogą szybciej i sprawniej dostosowywać swoje zabezpieczenia, żeby przeciwdziałać coraz to nowym zagrożeniom. Dostawcy chmury posiadają już duże doświadczenie w tym temacie, a ponadto są w stanie budować inteligentne rozwiązania z zakresu cyberbezpieczeństwa opierające się na heurystyce i uczeniu maszynowym, dzięki analizie ogromnej ilości danych, do których mają dostęp.

# Zagrożenia

W tej sekcji przyjrzymy się pokrótce różnym zagrożeniom i potencjalnym atakom, które są charakterystyczne dla systemów działających w chmurze. Najpopularniejsze to:

Niewłaściwa konfiguracja (ang. misconfiguration) - jest to chyba najbardziej podstawowe zagrożenie dla naszych zasobów działających w chmurze. Jeśli nie przyłożymy się do poprawnej konfiguracji usług, z których korzystamy może okazać się, że np. przez przypadek dopuściliśmy do zaindeksowania prywatnych zasobów przez wyszukiwarkę Google. W związku z tym bardzo ważne jest posiadanie odpowiedniego zespołu IT, który ma doświadczenie w pracy z usługami chmurowymi.

Utrata lub wyciek danych (ang. data loss/leakage) - w większości przypadków chmura publiczna jest dostępna przez Internet, co ułatwia udostępnianie zasobów innym, np. za pomocą specjalnego adresu URL. To również zwiększa ryzyko przypadkowego ujawnienia danych poprzez niezamierzone udostępnienie linka niepowołanym osobom. Wprawdzie odpowiednia konfiguracja powinna odrzucić wszystkie nieautoryzowane próby dostępu nawet dla posiadaczy prawidłowego adresu URL, ale już sama znajomość linka może dać atakującemu pewne pojęcie o wykorzystywanej pod spodem infrastruktury.

Przypadkowe ujawnienie danych uwierzytelniających (ang. credentials exposure) - usługi w chmurze przyzwyczaiły użytkowników do otrzymywania w mailach różnej maści linków potwierdzających. Ten fakt może być wykorzystany do opracowania skutecznych ataków phishingowych i wyłudzenia danych uwierzytelniających (credentials), co oczywiście może doprowadzić do przejęcia konta należącego do ofiary (ang. account hijacking) i co za tym idzie, wycieku bądź utraty danych. Pamiętajmy jednak, że takie scenariusze są przeważnie realizowane wskutek niedbałości użytkowników, którzy nie przestrzegają zaleconych procedur.

Nieautoryzowany dostęp (ang. unathourized access) - czyli dostęp do zasobów prywatnych przez nieautoryzowane osoby, który jest bezpośrednim skutkiem zlekceważenia trzech zagrożeń przedstawionych powyżej.

Zagrożenia wewnętrzne (ang. malicious insiders) - dużo groźniejsze, bo też i najmniej spodziewane, są ataki z wewnątrz. W tym przypadku nie chodzi nawet o nieuczciwych pracowników, którzy chcą nam poważnie zaszkodzić (choć taki scenariusz też jest możliwy), ale o sytuację, w której konto jednego z Twoich autoryzowanych użytkowników zostanie niepostrzeżenie skompromitowane. W związku z tym, nawet jeśli mamy pełne zaufanie do naszych pracowników/współpracowników (co w zasadzie powinno być naturalnym stanem rzeczy), to nie przyznawajmy im uprawnień szerszych nich rzeczywiście potrzebują.

Blokada usługi (ang. Denial of Service, DoS) - chodzi oczywiście o uniemożliwienie działania naszych usług przez jak najdłuższy czas. O ile atak bezpośrednio na infrastrukturę dostawcy CSP raczej mija się z celem, to nasza usługa/aplikacja może być podatna, nawet jeśli jest hostowana w chmurze.

    Przykład z życia wzięty: pracowałem kiedyś przy projekcie webowym hostowanym w środowisku Azure (jako App Service), gdzie również była skonfigurowana brama Azure Application Gateway, przez którą przechodził cały ruch sieciowy aplikacji. Brama odpowiadała m.in. za rozdzielanie ruchu do działających równolegle instancji aplikacji webowej (ang. load balancing), więc musiała jakoś sprawdzać czy poszczególne instancje działają jak należy. Robiła to za pomocą mechanizmu health probes, który polegał na regularnym wysyłaniu małych zapytań HTTP(S) do instancji, oczekując odpowiedzi HTTP 200 OK - kiedy odpowiedź wskazywała na problem (4xx lub 5xx), brama uznawała instancję za wadliwą i odcinała ją na pewien czas, przekierowując ruch do pozostałych instancji. Jak się zapewne domyślasz, w samej aplikacji był pewien błąd i kiedy przychodziły do nas żądania z publicznej sieci, które miały specyficzną budowę (mimo to przepuszczone przez WAF), aplikacja nagle zaczynała zwracać odpowiedź 400 Bad Request nawet na zwykłe żądania HTTP. To oczywiście spowodowało, że brama uznawała naszą aplikację za niedostępną, odcinając ostatecznie ruch dla wszystkich instancji. Skutkiem tego, cała aplikacja stawała się przez kilka minut niedostępna dla wszystkich użytkowników.

Myślę, że do tej grupy zagrożeń można jeszcze zaliczyć celowe obciążenie usług celem wygenerowania jak największych kosztów (np. przez nieuczciwą konkurencję), którymi CSP obciąży organizację, jeśli ta odpowiednio się nie zabezpieczy.

Podatności w API (ang. API vulnerabilities) - bardzo często CSP, oprócz graficznych interfejsów użytkownika, udostępniają tzw. programistyczny interfejs aplikacji (API = Application Programming Interface), z którym mogą integrować się inne aplikacje. Dzięki temu bardzo wiele zadań można zautomatyzować za pomocą skryptów. Teoretycznie mogą zdarzyć luki bezpieczeństwa w samej implementacji API, ale są to raczej bardzo rzadkie przypadki. Większość problemów wynika jednak z nieumiejętnego korzystania z danego API, braku odpowiednich zabezpieczeń oraz błędów w integracji. Pamiętajmy, że API udostępnione przez dostawcę usług chmurowych jest przeważnie dostępne publicznie wraz z całą dokumentacją, więc ktoś z dużym zacięciem oraz odpowiednią wiedzą może znaleźć słabe punkty w naszej integracji.
