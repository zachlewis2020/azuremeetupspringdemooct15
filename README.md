# azuremeetupspringdemooct15
Demo App for Azure Meetup Oct 15 
 git clone https://github.com/zachlewis2020/azuremeetupspringdemooct15

cd azuremeetupspringdemooct15

 mvn clean package

 java -jar target/*.jar

 az spring-cloud app deploy -g AzureSpringBootDemo -s azuremeetupoct15 -n springdemo1 --jar-path target/demo-0.0.1-SNAPSHOT.jar
