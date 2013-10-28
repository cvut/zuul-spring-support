package cz.cvut.zuul.oarp.spring

import org.codehaus.jackson.map.ObjectMapper
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.test.web.client.MockRestServiceServer
import org.springframework.web.client.RestTemplate
import spock.lang.Specification
import spock.lang.Unroll

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import static org.springframework.http.MediaType.APPLICATION_JSON
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess

/**
 * @author Jakub Jirutka <jakub@jirutka.cz>
 */
class StandaloneResourceServerTokenServicesTest extends Specification {

    static ENDPOINT_URL = "http://oauth-server.dev/api/check-token"
    static TOKEN_PARAM = "token_param"

    def restTemplate = new RestTemplate()
    def mockServer = MockRestServiceServer.createServer(restTemplate)
    def service = newTokenServices()


    def 'should load authentication for given token'() {
        setup:
            def body = new ObjectMapper().writeValueAsString(tokenInfo)
            mockServer.expect( anything() )
                    .andRespond( withSuccess(body, APPLICATION_JSON) )
        when:
            def response = service.loadAuthentication('meh')
        then:
            with (response.authorizationRequest) {
                clientId    == tokenInfo.clientId
                scope       == tokenInfo.scope
                resourceIds == tokenInfo.audience
                authorities == tokenInfo.clientAuthorities
            }
        and:
            if (clientOnly) {
                assert response.clientOnly
            } else {
                assert response.userAuthentication.principal == tokenInfo.userId
            }
        where:
            clientOnly << [true, false]
            tokenInfo = tokenInfo(clientOnly)
    }

    @Unroll
    def 'should throw exception when response #message'() {
        setup:
            mockServer.expect(anything()).andRespond(respond)
        when:
            service.loadAuthentication('meh')
        then:
            thrown exception
        where:
            message           | respond                                              || exception
            'is empty'        | withSuccess('{ }', APPLICATION_JSON)                 || IllegalStateException
            'lacks client_id' | withSuccess(tokenInfoAsJson(null), APPLICATION_JSON) || IllegalStateException
            'status is 409'   | withStatus(HttpStatus.CONFLICT)                      || InvalidClientTokenException
    }

    def 'verify POST request'() {
        setup:
            def service = newTokenServices(HttpMethod.POST)
            def tokenValue = "dummy-token"

            mockServer.expect( requestTo(ENDPOINT_URL) )
                   .andExpect( method(HttpMethod.POST) )
                   .andExpect( content().contentType(APPLICATION_FORM_URLENCODED) )
                   .andExpect( content().string("${TOKEN_PARAM}=${tokenValue}") )
                   .andRespond( withSuccess(tokenInfoAsJson(), APPLICATION_JSON) )
        when:
            service.loadAuthentication(tokenValue)
        then:
            mockServer.verify()
    }

    def 'verify GET request'() {
        setup:
            def service = newTokenServices(HttpMethod.GET)
            def tokenValue = "dummy-token"

            mockServer.expect( requestTo("${ENDPOINT_URL}?${TOKEN_PARAM}=${tokenValue}") )
                    .andExpect( method(HttpMethod.GET) )
                    .andRespond( withSuccess(tokenInfoAsJson(), APPLICATION_JSON) )
        when:
            service.loadAuthentication(tokenValue)
        then:
            mockServer.verify()
    }


    def tokenInfo(boolean clientOnly = false, String clientId = 'client123') {
        new TokenInfo(
                clientId: clientId,
                scope: ['urn:ctu:oauth:sample.read'],
                audience: ['service123'],
                expiresIn: 60,
                userId: clientOnly ? null : 'tomy'
        )
    }

    def tokenInfoAsJson(String clientId = 'client123') {
        new ObjectMapper()
                .writeValueAsString( tokenInfo(false, clientId) )
    }

    def newTokenServices(method = HttpMethod.POST) {
        def service = new StandaloneResourceServerTokenServices(
                restTemplate: restTemplate,
                checkTokenEndpointUrl: ENDPOINT_URL,
                tokenParameterName: TOKEN_PARAM,
                method: method
        )
        service.afterPropertiesSet()
        service
    }
}
