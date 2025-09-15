# 2.5 Explain the purpose of mitigation techniques used to secure the enterprise
Wyjaśnij przeznaczenie technik zapobiegawczych, stosowanych do ochrony organizacji.
# Hardening techniques
Kiedy instalujemy świeżą aplikację, system operacyjny bądź dodajemy do naszej infrastruktury nowe urządzenie, przeważnie polegamy na domyślnej konfiguracji, która nie zawsze jest bezpieczna.

Wprawdzie są dostawcy (ang. *vendors*), którzy tworzą swoje produkty mając na względzie bezpieczeństwo w pierwszej kolejności (ang. *security-first approach*), jednakże nawet wtedy nie mamy pewności, że dana konfiguracja domyślna będzie niezawodna w naszym konkretnym przypadku.

***Hardening*** (w dosłownym tłumaczeniu: hartowanie, utwardzanie) to **proces wprowadzania zmian konfiguracyjnych aplikacji, systemu bądź urządzenia celem zwiększenia poziomu ich bezpieczeństwa oraz ograniczenia obszaru podatności na ewentualne ataki.**
## Od czego zacząć?
Przed przystąpieniem do procesu *utwardzania* konfiguracji, istotna jest **identyfikacja obszarów, które wymagają poprawy.** Poza tym bardzo ważne jest **dostosowanie całego procesu do potrzeb naszych i/lub naszej organizacji**. 

Pierwszym krokiem powinno być **opracowanie planu** operacji *hardeningu*, który mógłby być wynikiem rzetelnej **analizy ryzyka**. Posiadanie takiego planu jest bardzo pomocne, ponieważ możemy wtedy skupić się tylko na tych obszarach, które są istotne z naszego punktu widzenia.

Kiedy wiemy już, co i gdzie może realnie zagrażać bezpieczeństwu naszych systemów, powinniśmy przystąpić do *dostrajania* konfiguracji. Niestety, nie jest to trywialne zadanie, ponieważ znajomość wszystkich możliwych ustawień konfiguracyjnych (nawet tylko tych wpływających na *odporność*) dla różnej maści aplikacji, systemów operacyjnych czy urządzeń, jest praktycznie niemożliwa.

Na szczęście dostawcy rozwiązań cyfrowych oraz sprzętowych, bardzo często udostępniają stosowne instrukcje (tzw. [*secure baselines*](https://vilya.pl/sy0-701-secure-baselines-pl/)), które w klarowny sposób opisują, krok po kroku, w jaki sposób można zabezpieczyć dany produkt. Pierwszy przykład z brzegu, czyli wydana przez Apple lista porad, pomagających zwiększyć bezpieczeństwo w systemie iOS (iPhone): [Use the built-in privacy and security protections of iPhone](https://support.apple.com/en-sa/guide/iphone/iph6e7d349d1/ios).

Jeśli oficjalny przewodnik nie jest ogólnodostępny, zawsze można wysłać bezpośrednie zapytanie do twórcy danego rozwiązania i poprosić o stosowne wskazówki. Szczególnie jeśli dostawca zobowiązał się do zapewnienia wsparcia (ang. *support*) w ramach umowy.

Oprócz instrukcji udostępnianych przez twórców rozwiązań, w internecie można znaleźć **dedykowane przewodniki opracowane przez firmy trzecie (ang. *third parties*), społeczności zainteresowane danym produktem, a nawet organizacje rządowe**. Na przykład:
- [CIS Benchmarks List](https://www.cisecurity.org/cis-benchmarks)
- [National Cecklist Program (NCP) repository](https://ncp.nist.gov/repository)
- [Australian Signals Directorate (ASD) - System hardening and administration](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration)

Jeśli przejrzymy sobie poszczególne instrukcje, możemy poczuć się lekko przytłoczeni, ponieważ niektóre opracowania są naprawdę obszerne i liczą nawet po kilkaset stron. Między innymi  dlatego warto mieć plan dostosowany do naszych potrzeb - dzięki temu możemy skoncentrować się tylko na tym, co jest istotne dla nas i naszej organizacji.

**Starajmy się zautomatyzować proces weryfikacji naszej aktualnej konfiguracji pod kątem bezpieczeństwa, jeśli tylko jest to możliwe**. Pozwoli nam to zaoszczędzić mnóstwo czasu, gdyż nie będziemy musieli ręcznie analizować każdego pojedynczego ustawienia za każdym razem (choć raz na jakiś czas warto samemu wszystko przejrzeć).

Oprócz typowych automatycznych skanerów podatności (ang. *vulnerability scanners*), takich jak [Nessus](https://www.tenable.com/products/nessus) czy [OpenVAS](https://www.openvas.org/), możemy posłużyć się narzędziami, których głównym zadaniem jest weryfikacja ustawień bezpieczeństwa na podstawie dołączonych wytycznych (*secure baselines*):
- [OpenSCAP](https://www.open-scap.org/) - zestaw narzędzi *open source*, opartych o protokół [SCAP](https://csrc.nist.gov/projects/security-content-automation-protocol/) (*Security Content Automation Protocol*), których zadaniem jest automatyzacja audytów zgodności z politykami bezpieczeństwa. Do działania wymaga bazy danych z regułami zdefiniowanymi w standardzie SCAP. Umożliwia skanowanie lokalne oraz zdalne.
- [CIS-CAT Lite](https://learn.cisecurity.org/cis-cat-lite) - kolejne darmowe narzędzie, utworzone przez organizację CIS (*Center for Internet Security*) do oceny zgodności badanego systemu z zdefiniowanymi wytycznymi bezpieczeństwa. Dostępna jest również wersja płatna (*CIS-CAT Pro*), która posiada trochę bardziej rozbudowane możliwości.
## Podstawowe zasady
Na rynku istnieje ogromna ilość najrozmaitszych urządzeń, aplikacji i systemów operacyjnych, które mogą się znacząco od siebie różnić. Oznacza to, że każdy z tych elementów może wymagać innego podejścia podczas *hardeningu*, jednakże możemy wyodrębnić pewien **uniwersalny zestaw dobrych praktyk** (ang. *best practices*):
1. **Regularnie instaluj aktualizacje i poprawki bezpieczeństwa** (ang. *security patches*), **kiedy tylko zostaną opublikowane**. 
	1. Aktualizacje mogą pojawiać się z różną częstotliwością, w zależności od producenta. Przykładowo, Microsoft publikuje swoje poprawki bezpieczeństwa Windows [w drugi wtorek każdego miesiąca](https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle#monthly-security-update-release), co nawet zyskało swoją swojską nazwę: *Patch Tuesday*. Oczywiście w przypadku nagłego pojawiania się poważnej podatności, której wykorzystanie może być katastrofalne w skutkach, łatki są wydawane tak szybko, jak tylko jest to możliwe.
	2. Każda aktualizacja może mieć istotny wpływ na działanie i stabilność naszych systemów, dlatego dobrze jest mieć w organizacji sformalizowany proces zarządzania zmianami (np. weryfikujemy zmiany wprowadzone przez aktualizację na jednym serwerze i dopiero później aktualizujemy pozostałe serwery). Pamiętajmy jednak, że krytyczne poprawki powinniśmy zainstalować jak najszybciej.
2. **Zmień domyślne poświadczenia uwierzytelniające** (ang. *credentials*). Niektóre urządzenia oraz aplikacje posiadają wbudowane konta użytkowników. Dostęp do nich jest możliwy po podaniu domyślnej nazwy użytkownika i hasła, które są często zapisane w dokumentacji (np. *admin/admin* lub *guest/guest*).
3. **Wyłącz nieużywane usługi**. Wyłączenie zbędnych usług (ang. *services*) działających w systemie nie tylko skutecznie ogranicza obszar potencjalnego ataku, ale może też wpłynąć pozytywnie na wydajność tegoż systemu.
4. **Zablokuj i wyłącz porty sieciowe oraz protokoły, które są nieużywane**. Przykładowo, jeśli nasza stacja robocza nie jest serwerem pocztowym, najprawdopodobniej nie potrzebujemy obsługi protokołu SMTP (*Simple Mail Transfer Protocol*) i powiązanego z nim otwartego portu 25. Analogicznie, jeśli nasza mała sieć LAN nie wymaga używania protokołu IPv6, to również możemy śmiało wyłączyć jego wsparcie.
5. **Odinstaluj zbędne oprogramowanie.** Im więcej linii kodu, tym większa szansa, że w aplikacji znajdzie się jakaś podatność. Usuwając *software*, którego nie potrzebujemy, zmniejszamy potencjalny obszar ataku.
6. **Chroń punkty krańcowe (ang. *endpoints*) sieci**, czyli podłączone do niej urządzenia i stacje robocze użytkowników, **poprzez ich monitorowanie oraz zabezpieczanie za pomocą odpowiedniego oprogramowania** (*anti-malware*, *host-based firewalls*, rozwiązania typu EDR, itp.).
7. **Szyfruj dane w spoczynku (ang. *at-rest*) oraz te transmitowane (ang. *in-transit*) przez sieć.** W przypadku danych *w spoczynku* możemy stosować szyfrowanie całych nośników danych bądź wybranych plików i folderów. Do przesyłania informacji używajmy bezpiecznych (szyfrowanych) protokołów typu HTTPS oraz SSH.
8. **Ogranicz dostęp do wrażliwych obszarów swojej sieci poprzez jej segmentację**, na przykład za pomocą wirtualnych sieci VLAN (*Virtual Local Area Networks*). Dobrym przykładem na potrzebę utworzenia osobnej sieci wirtualnej mogą być urządzenia IoT (*Internet of Things*), które często są niewystarczająco zabezpieczone. Nawet w przypadku kompromitacji takiego urządzenia, intruz uzyska dostęp jedynie do wydzielonego obszaru naszej sieci.
9. **Jeśli to możliwe, nie pozwalaj na dostęp do swojej sieci przypadkowym urządzeniom**. W ramach sieci wewnętrznej organizacji, raczej nie chcemy, żeby każde urządzenie otrzymywało dostęp zaraz po podłączeniu. Wyjątkiem mogą być goście, którzy potrzebują jedynie tymczasowego i ograniczonego dostępu.
## Encryption
**Szyfrowanie** (ang. *encryption*) to, w dużym skrócie, **proces transformacji czytelnych danych do postaci niezrozumiałego tekstu(*ciphertext*), który wygląda jak losowy ciąg znaków.** Odczytanie pierwotnej informacji jest niemożliwe bez wcześniejszego odszyfrowania (ang. *decryption*) zakodowanej wiadomości, z użyciem odpowiedniego klucza.

Jest to czynność niezwykle istotna podczas zabezpieczania naszych systemów, gdyż **chroni wrażliwe dane przed nieautoryzowanym dostępem**, zarówno te przechowywane na nośnikach (*data at-rest*), jak i przesyłane przez sieć (*data in-transit/in-motion*).

W przypadku danych transmitowanych przez sieć, jedną z podstawowych czynności zabezpieczających jest **stosowanie protokołów komunikacyjnych zapewniających szyfrowanie** (np. HTTPS, SSH, SFTP). Nawet jeśli atakujący będzie w stanie podejrzeć taki ruch, to i tak nie uzyska żadnych sensownych informacji.

Jeśli zaś chodzi o **szyfrowanie danych w spoczynku**, to możemy się zastanawiać, po co zawracać sobie tym głowę, skoro i tak dostęp do serwerów czy stacji roboczych, na których są przechowywane dane, jest ograniczony jedynie do autoryzowanych użytkowników. Może się jednak zdarzyć, że służbowy laptop zaginie lub zostanie skradziony. W takim przypadku, jeśli dane są niezaszyfrowane, osoba nieupoważniona nie będzie miała najmniejszego problemu z ich odczytaniem.

Nawet jeśli dostęp do systemu operacyjnego jest zabezpieczony hasłem, to przecież nic nie stoi na przeszkodzie, żeby uruchomić inny system typu [Live CD](https://pl.wikipedia.org/wiki/Live_CD) i za jego pośrednictwem uzyskać dostęp do wybranej partycji. Gdyby jednak cały dysk, partycja bądź tylko istotne pliki zostały wcześniej zaszyfrowane, ich odczytanie byłoby praktycznie niemożliwe.

Innym scenariuszem, który warto wziąć pod uwagę, jest wymiana sprzętu w organizacji.
Kiedy pozbywamy się starych dysków, powinniśmy je co prawda całkowicie wyczyścić, ale może się zdarzyć, wskutek pomyłki w ogóle to nie nastąpi. Samo formatowanie może okazać się nie do końca skuteczne i osoba, która otrzyma nośnik *w spadku* będzie w stanie odzyskać część (jeśli nie całość) danych.

Kiedy jednak wrażliwe dane zostały wcześniej odpowiednio zaszyfrowane, opisane wyżej incydenty mogą być traktowane jako **utrata danych**, a nie **wyciek danych**, co z prawnego punku widzenia stanowi kolosalną różnicę.
## Installation of endpoint protection
TBD
## Host-based firewall
TBD
## Host-based intrusion prevention system (HIPS)
TBD
## Disabling ports/protocols
TBD
## Default password changes
TBD
## Removal of unnecessary software
TBD
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
- [Hardening od podstaw, czyli jak ze swojej organizacji zrobić twierdzę nie do zdobycia?](https://integritypartners.pl/podstawy-hardeningu-czyli-jak-ze-swojej-organizacji-zrobic-twierdze-nie-do-zdobycia/)