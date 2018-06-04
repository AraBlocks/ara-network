FROM node
WORKDIR /opt/ann
ADD . /opt/ann
RUN npm link
