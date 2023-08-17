# sspk_api
1.Создаем тестовый docker контейнер с базой данных
docker run --rm -e POSTGRES_PASSWORD=secret -e POSTGRES_USER=user -e POSTGRES_DB=restapi_dev --name=pg -p 5432:5432 -v pgdb:/var/lib/postgresql/data postgres
2.Проводим миграции
