# net-creds
Утилита сниффит пароли и хэши из интерфейса или pcap файла. Конкатенирует фрагментированные пакеты и не полагается на номера портов для идентификации сетевых служб.

Все изменения, выполненные в рамках данного форка, являются ходом работы над практическим заданием от предприятия ООО "Уральский Центр Систем Безопасности".
## TODO
Модернизация:
- [x] Переход на 3 версию Python ([a05c6a](https://github.com/pavelslabikov/net-creds/commit/a05c6a421e427ee9cd3597c9e656220065a1c26f))
- [x] Поддержка ОС Windows ([c307a2](https://github.com/pavelslabikov/net-creds/commit/c307a290c49a0bdda8f05d5c1fff4cb5855010e3))
- [x] Переработка логики вывода результата + логгирование ([43a2e5](https://github.com/pavelslabikov/net-creds/commit/43a2e5982c279526cefb3614e3390594a6477b84))

Рефакторинг:
- [x] Реструктуризация проекта ([f805a0](https://github.com/pavelslabikov/net-creds/commit/f805a0a3bd33d350e90c5c587f40f47944164193))
- [x] Создание доменной модели ([d9be1e](https://github.com/pavelslabikov/net-creds/commit/d9be1e453d829bd14ce1b6dd9fd3a73c12d8cd47))

Тестирование:
- [x] Подбор для каждого протокола по .pcap файлу, содержащего креды ([167550](https://github.com/pavelslabikov/net-creds/commit/1675508e5c83c56cd3c737206b2a63d5d55c145e))
- [x] Написание интеграционных тестов с подобранными .pcap файлами ([df65fd](https://github.com/pavelslabikov/net-creds/commit/df65fd14263584af5e09a0be5a45dde8d5fa1789))


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

## Установка
Поддерживаемая версия Python >= 3.7
```commandline
git clone https://github.com/pavelslabikov/net-creds.git
cd net-creds
pip install -r requirements.txt
```

## Примеры запуска

### Linux

Автоопределение интерфейса для сниффинга (выбирается первый попавшийся активный)

`sudo python3 -m net_creds`

Выбор eth0 для сниффинга

`sudo python3 -m net_creds -i eth0`

Игнорирование пакетов от и до 192.168.0.2

`sudo python3 -m net_creds -f 192.168.0.2`

Чтение из pcap файла

`sudo python3 -m net_creds -p pcapfile`

### Windows
Выбор сетевого адаптера с именем "Беспроводная сеть" для сниффинга:

`python -m net_creds -i "Беспроводная сеть"`

## Благодарности
* Laurent Gaffie
* psychomario
