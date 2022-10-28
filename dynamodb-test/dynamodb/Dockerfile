# Using official dynamodb-local image 
FROM amazon/dynamodb-local:latest
# Set user to root
USER root
# Set workdir to home directory
WORKDIR /home/dynamodblocal/

# Copy modified log4j.xml to the home directory
COPY ./log4j2.xml /home/dynamodblocal/
# Install zip using yum
RUN yum install --assumeyes --quiet zip
# Replace the log4j.xml inside DynamoDBLocal.jar with the new log4j.xml
RUN zip -d DynamoDBLocal.jar log4j2.xml && zip -u DynamoDBLocal.jar ./log4j2.xml

# Run java with args given below
ENTRYPOINT [ "java" ]
# Run the following command on entry
CMD ["-jar", "DynamoDBLocal.jar", "-sharedDb", "-dbPath", "/home/dynamodblocal/data"]