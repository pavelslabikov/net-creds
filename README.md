# net-creds
Утилита сниффит пароли и хэши из интерфейса или pcap файла. Конкатенирует фрагментированные пакеты и не полагается на номера портов для идентификации сетевых служб.

Все изменения, выполненные в рамках данного форка, являются ходом работы над практическим заданием от предприятия ООО "Уральский Центр Систем Безопасности".
## TODO
Модернизация:
- [x] Переход на 3 версию Python
- [x] Поддержка ОС Windows
- [x] Переработка логики вывода результата + логгирование

Рефакторинг:
- [x] Реструктуризация проекта
- [x] Создание доменной модели

Тестирование:
- [x] Подбор для каждого протокола по .pcap файлу, содержащего креды
- [x] Написание интеграционных тестов с подобранными .pcap файлами


## Функциональные возможности
Сниффит:
* Посещённые URLs
* POST loads sent
* HTTP form logins/passwords
* HTTP basic auth logins/passwords
* FTP logins/passwords
* IRC logins/passwords
* POP logins/passwords
* IMAP logins/passwords
* Telnet logins/passwords
* SMTP logins/passwords
* SNMP community string
* NTLMv1/v2 all supported protocols: HTTP, SMB, LDAP, etc.
* Kerberos

## Примеры запуска

### Linux

Автоопределение интерфейса для сниффинга (выбирается первый попавшийся активный)

`sudo python -m net_creds`

Выбор eth0 для сниффинга

`sudo python -m net_creds -i eth0`

Игнорирование пакетов от и до 192.168.0.2

`sudo python -m net_creds -f 192.168.0.2`

Чтение из pcap файла

`python -m net_creds -p pcapfile`

## Благодарности
* Laurent Gaffie
* psychomario
