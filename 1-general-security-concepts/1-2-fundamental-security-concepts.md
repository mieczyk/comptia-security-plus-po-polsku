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
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
- [PushSec: Brak znajomości CIA wstrzymywał moją karierę](https://pushsec.pl/brak-znajomosci-cia-wstrzymywalo-moja-kariere/)