# Datum - Приложение для знакомств

`run.cmd` - для установки необходимых пакетов для проекта

Для настройки сайта необходимо создать администратора командой `python manage.py createsuperuser`. После запуска веб-приложения (как это сделать ниже) зайти в админку, открыть базу с сайтами и поменять запись с `example.com` на `localhost:8000` или свой домен, отображаемое имя - произвольное.

Для запуска веб-приложения на локальном хосте выполните:
1) `venv\Scripts\activate`
2) `cd Datum`
3) `python manage.py makemigrations`
4) `python manage.py migrate`
5) `python manage.py runserver`
