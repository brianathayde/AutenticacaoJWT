# AutenticacaoJWT
Projeto utilizando .NET CORE 8.

Aqui existe a lógica para gerar tokens de acesso, refresh tokens, revogar tokens e a partir disso
é possivel fazer a autenticação e autorização de rotas.

## Migrations:

Primero é necessário instalar o dotnet-ef com o seguinte comando:

$ dotnet tool install --global dotnet-ef

Para executar as migratios é use o comando:

$ dotnet ef database update

Na pasta ./AutenticacaoJWT/Database/AutenticacaoJWT contém o arquivo docker-compose.yml para subir o conteiner com o banco de dados PostgreSQL usado para os testes.

## Importante:

É **extremamente** recomendável alterar os usuários, senhas, email, Jwt:Key, etc caso for utilizar esse código em ambiente de produção. Tudo aqui foi feito somente para fins de demosntração e testes.
