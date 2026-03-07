FROM httpd:alpine
EXPOSE 443

COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY cert.pem /usr/local/apache2/conf/cert.pem
COPY key.pem /usr/local/apache2/conf/key.pem