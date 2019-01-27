import org.springframework.boot.{ApplicationRunner, SpringApplication}
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.{Bean, ComponentScan}
import org.springframework.web.client.RestTemplate

@SpringBootApplication
@ComponentScan(basePackages = Array("authenticationserver"))
class Application{

  @Bean
  def init(): ApplicationRunner = args => {

  }

  @Bean
  def restTemplate() : RestTemplate = new RestTemplate()
}


object Application extends App {
  SpringApplication.run(classOf[Application], args: _*)
}
