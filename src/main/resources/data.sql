DELETE FROM oauth_client_details;

INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types,
	web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	("microservice-portal", "123456", "microservice-portal.access,microservice-portal.admin",
	"password,authorization_code,refresh_token", null, 'microservice-portal.access', 1800, 1800, null, true);

INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types,
	web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	("backend-services", "ivtprt@microservices", "admin,microservice.read,microservice.write",
	"client_credentials", null, null, 36000, 36000, null, true);