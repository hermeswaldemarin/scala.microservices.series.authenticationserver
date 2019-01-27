package autenticationserver.configuration

import java.security.NoSuchProviderException
import java.sql.{PreparedStatement, ResultSet, SQLException}
import java.util
import java.util.{Map, UUID}

import autenticationserver.services.UserService
import javax.sql.DataSource
import org.apache.commons.lang3.RandomStringUtils.randomAlphabetic
import org.springframework.beans.factory.annotation.{Autowired, Qualifier, Value}
import org.springframework.context.annotation.{Bean, Configuration, Primary}
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.core.io.{ClassPathResource, Resource}
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.springframework.jdbc.datasource.init.{DataSourceInitializer, ResourceDatabasePopulator}
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider
import org.springframework.security.authentication.{AuthenticationManager, BadCredentialsException, InternalAuthenticationServiceException, UsernamePasswordAuthenticationToken}
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.{User, UserDetails, UserDetailsService, UsernameNotFoundException}
import org.springframework.security.oauth2.common.{DefaultOAuth2AccessToken, OAuth2AccessToken}
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.{AuthorizationServerConfigurerAdapter, EnableAuthorizationServer}
import org.springframework.security.oauth2.config.annotation.web.configurers.{AuthorizationServerEndpointsConfigurer, AuthorizationServerSecurityConfigurer}
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory
import org.springframework.security.oauth2.provider.token.store.{JdbcTokenStore, JwtAccessTokenConverter, KeyStoreKeyFactory}
import org.springframework.security.oauth2.provider.token.{DefaultTokenServices, TokenEnhancer, TokenEnhancerChain}
import org.springframework.security.oauth2.provider.{ClientDetailsService, OAuth2Authentication}
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.stereotype.Component
import org.springframework.util.Assert


@Component
@Order(200)
class CustomAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider{
  val externaltoken : String = "externaltoken";

  @Autowired(required = true) private val userDetailsService : UserDetailsService = null

  @Autowired var userService: UserService = null

  override def additionalAuthenticationChecks(userDetails: UserDetails, usernamePasswordAuthenticationToken: UsernamePasswordAuthenticationToken): Unit = {
    var details = usernamePasswordAuthenticationToken.getDetails().asInstanceOf[Map[String, String]];
    if (details.get(externaltoken) != null && !("" == details.get(externaltoken))) {
      val externalToken = details.get(externaltoken).asInstanceOf[String]
      val externalProvider = details.get("externalprovider").asInstanceOf[String]
      try
        this.userService.checkExternalProviderCredentials(externalProvider, externalToken, userDetails.asInstanceOf[CustomUserDetails].getExternalid)
      catch {
        case e: NoSuchProviderException =>
          throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"))
      }
    }
    else {
      val presentedPassword = usernamePasswordAuthenticationToken.getCredentials.toString
      if (!(userDetails.getPassword == presentedPassword)) throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"))
    }

  }

  override def retrieveUser(username: String, usernamePasswordAuthenticationToken: UsernamePasswordAuthenticationToken): UserDetails = {
    var loadedUser : UserDetails = null
    try
      loadedUser = userDetailsService.loadUserByUsername(username)
    catch {
      case var6: UsernameNotFoundException =>
        throw var6
      case var7: Exception =>
        throw new InternalAuthenticationServiceException(var7.getMessage, var7)
    }

    if (loadedUser == null) throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation")
    else return loadedUser
  }

  override def supports(authentication: Class[_]): Boolean = authentication == classOf[UsernamePasswordAuthenticationToken]
}


@Configuration
@Order (100)
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired private val authProvider : CustomAuthenticationProvider = null

  @throws[Exception]
  override protected def configure(auth: AuthenticationManagerBuilder): Unit = {
    auth.authenticationProvider(authProvider)
  }

  @Bean
  @throws[Exception]
  override def authenticationManagerBean: AuthenticationManager = super.authenticationManagerBean

  @throws[Exception]
  override protected def configure(http: HttpSecurity): Unit = {
    http.authorizeRequests.antMatchers("/login", "/oauth/token/revokeById/**", "/tokens/**", "/user-create/**", "/confirm-token/**").permitAll.anyRequest.authenticated.and.formLogin.permitAll.and.csrf.disable
  }
}



class CustomJdbcUserDetailsManager extends JdbcUserDetailsManager{
  private val externalIdByUsername: String = "select externalid from users where username = ?"
  private val createUserSql: String = "insert into users (username, password,externalid, enabled) values (?,?,?,?)"
  private val createAuthoritySql: String = "insert into authorities (username, authority) values (?,?)"
  private val createEmailTokenSql: String = "insert into mailtoken (username, token) values (?,?)"
  private val getUserNameByEmailToken: String = "select username from mailtoken where token = ?"

  override def loadUserByUsername(username: String): UserDetails = {
    val user: UserDetails = super.loadUserByUsername(username)
    var externalid: String = null
    val external: util.List[String] = loadExternalId(username)
    if (external.get(0) != null && !(external.get(0) == "")) externalid = external.get(0)
    new CustomUserDetails(user, externalid)
  }

  protected def loadExternalId(username: String): util.List[String] = return this.getJdbcTemplate.query(this.externalIdByUsername, new RowMapper[String]() {
    @throws[SQLException]
    override def mapRow(rs: ResultSet, rowNum: Int): String = rs.getString(1)
  }, username)

  def createUser(user: CustomUserDetails): Unit = {
    validateUserDetailsCustom(user)
    getJdbcTemplate.update(createUserSql, (ps: PreparedStatement) => {
      ps.setString(1, user.getUsername)
      ps.setString(2, user.getPassword)
      ps.setString(3, user.getExternalid)
      ps.setBoolean(4, user.isEnabled)
    })
    if (getEnableAuthorities) insertUserAuthoritiesCustom(user)
  }

  private def validateUserDetailsCustom(user: UserDetails): Unit = {
    Assert.hasText(user.getUsername, "Username may not be empty or null")
    validateAuthoritiesCustom(user.getAuthorities)
  }

  private def validateAuthoritiesCustom(authorities: util.Collection[_ <: GrantedAuthority]): Unit = {
    Assert.notNull(authorities, "Authorities list must not be null")
    import scala.collection.JavaConversions._
    for (authority <- authorities) {
      Assert.notNull(authority, "Authorities list contains a null entry")
      Assert.hasText(authority.getAuthority, "getAuthority() method must return a non-empty string")
    }
  }

  private def insertUserAuthoritiesCustom(user: UserDetails): Unit = {
    import scala.collection.JavaConversions._
    for (auth <- user.getAuthorities) {
      getJdbcTemplate.update(createAuthoritySql, user.getUsername, auth.getAuthority)
    }
  }

  def getUserNameByToken(emailToken: String): String = {
    val data: util.List[String] = this.getJdbcTemplate.query(getUserNameByEmailToken, new RowMapper[String]() {
      @throws[SQLException]
      override def mapRow(rs: ResultSet, rowNum: Int): String = rs.getString(1)
    }, emailToken)
    Assert.notEmpty(data, "Invalid Token")
    data.get(0)
  }

  def createMailToken(user: UserDetails): String = {
    val token: String = UUID.randomUUID.toString
    getJdbcTemplate.update(createEmailTokenSql, user.getUsername, token)
    token
  }
}

class CustomUserDetails(var user: UserDetails, var externalid: String) extends User(user.getUsername, user.getPassword, user.isEnabled, user.isAccountNonExpired, user.isCredentialsNonExpired, user.isAccountNonLocked, user.getAuthorities){

  def getExternalid: String = externalid

  def setExternalid(externalid: String): Unit = {
    this.externalid = externalid
  }

  def getUser: UserDetails = user

  def setUser(user: UserDetails): Unit = {
    this.user = user
  }
}

class CustomTokenEnhancer extends TokenEnhancer{
  override def enhance(accessToken: OAuth2AccessToken, authentication: OAuth2Authentication): OAuth2AccessToken = {
    val additionalInfo = new util.HashMap[String, AnyRef]
    additionalInfo.put("organization", authentication.getName + randomAlphabetic(4))
    accessToken.asInstanceOf[DefaultOAuth2AccessToken].setAdditionalInformation(additionalInfo)
    accessToken
  }
}

@Configuration
@EnableAuthorizationServer
class OAuth2AuthorizationServerConfigJwt extends AuthorizationServerConfigurerAdapter {

  @Autowired val clientDetailsService : ClientDetailsService = null

  @Autowired
  @Qualifier("authenticationManagerBean") private val authenticationManager : AuthenticationManager = null

  @Autowired private val env : Environment = null

  @Value("classpath:schema.sql") private val schemaScript : Resource = null

  @Value("classpath:data.sql") private val dataScript : Resource = null

  @throws[Exception]
  override def configure(oauthServer: AuthorizationServerSecurityConfigurer): Unit = {
    oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()")
  }

  @throws[Exception]
  override def configure(clients: ClientDetailsServiceConfigurer): Unit = {
    clients.jdbc(dataSource)
  }

  @Bean def dataSourceInitializer(dataSource: DataSource): DataSourceInitializer = {
    val initializer = new DataSourceInitializer
    initializer.setDataSource(dataSource)
    initializer.setDatabasePopulator(databasePopulator)
    initializer
  }

  private def databasePopulator = {
    val populator = new ResourceDatabasePopulator
    populator.addScript(schemaScript)
    populator.addScript(dataScript)
    populator
  }

  @Bean def dataSource: DataSource = {
    val dataSource = new DriverManagerDataSource
    dataSource.setDriverClassName(env.getProperty("spring.jdbc.driverClassName"))
    dataSource.setUrl(env.getProperty("spring.jdbc.url"))
    dataSource.setUsername(env.getProperty("spring.jdbc.user"))
    dataSource.setPassword(env.getProperty("spring.jdbc.pass"))
    dataSource
  }

  @Bean
  @Primary def tokenServices: DefaultTokenServices = {
    val defaultTokenServices = new DefaultTokenServices
    defaultTokenServices.setTokenStore(tokenStore)
    defaultTokenServices.setSupportRefreshToken(true)
    defaultTokenServices
  }

  @throws[Exception]
  override def configure(endpoints: AuthorizationServerEndpointsConfigurer): Unit = {
    val tokenEnhancerChain = new TokenEnhancerChain
    tokenEnhancerChain.setTokenEnhancers(util.Arrays.asList(tokenEnhancer, accessTokenConverter))
    val requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService)
    requestFactory.setCheckUserScopes(true)
    endpoints.tokenStore(tokenStore).tokenEnhancer(tokenEnhancerChain).requestFactory(requestFactory).authenticationManager(authenticationManager)
  }

  @Bean def userDetailsService: UserDetailsService = {
    val userDetailsService = new CustomJdbcUserDetailsManager
    userDetailsService.setEnableGroups(true)
    userDetailsService.setDataSource(dataSource)
    userDetailsService
  }

  @Bean def tokenStore = new JdbcTokenStore(dataSource)

  @Bean def accessTokenConverter: JwtAccessTokenConverter = {
    val converter = new JwtAccessTokenConverter
    val keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("microservices.jks"), "microservices@2018".toCharArray)
    converter.setKeyPair(keyStoreKeyFactory.getKeyPair("microservices"))
    converter
  }

  @Bean def tokenEnhancer = new CustomTokenEnhancer
}


