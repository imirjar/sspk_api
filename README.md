# sspk_api
I Запуск
    1.Создаем тестовый docker контейнер с базой данных
        sudo docker run --rm -e POSTGRES_PASSWORD=secret -e POSTGRES_USER=user -e POSTGRES_DB=restapi_dev --name=rb_database -p 5432:5432 -v pgdb:/var/lib/postgresql/data postgres

        --rm Automatically remove the container when it exits
        -e Set environment variables
        -v Bind mount a volume

        docker run -e POSTGRES_PASSWORD=secret -e POSTGRES_USER=user -e POSTGRES_DB=restapi_dev --name=rb_database -p 5432:5432 -v pgdb:/var/lib/postgresql/data -d postgres

    2.Проводим миграции
        ./migrate -path migrations  -database "postgres://user:secret@localhost/restapi_dev?sslmode=disable" up
    2 Откат миграций
        ./migrate -path migrations  -database "postgres://user:secret@localhost/restapi_dev?sslmode=disable" down

    3.Проверка API
        3.1 Регистрация
        http POST http://localhost:8080/users email=user@examplez.org password=password
        3.1 Аутентификация
        http POST http://localhost:8080/sessions email=user@examplez.org password=password