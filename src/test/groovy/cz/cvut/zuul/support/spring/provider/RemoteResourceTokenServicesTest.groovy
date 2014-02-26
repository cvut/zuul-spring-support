/*
 * The MIT License
 *
 * Copyright 2013-2014 Czech Technical University in Prague.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package cz.cvut.zuul.support.spring.provider

import org.codehaus.jackson.map.ObjectMapper
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.test.web.client.MockRestServiceServer
import org.springframework.web.client.RestTemplate
import spock.lang.Specification
import spock.lang.Unroll

import static org.springframework.http.MediaType.APPLICATION_JSON
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess

class RemoteResourceTokenServicesTest extends Specification {

    static ENDPOINT_URL = "http://oauth-server.dev/api/v1/tokeninfo"
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

    def 'should perform GET request to tokeninfo'() {
        setup:
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

    def newTokenServices() {
        def service = new RemoteResourceTokenServices(
                restTemplate: restTemplate,
                tokenInfoEndpointUrl: ENDPOINT_URL,
                tokenParameterName: TOKEN_PARAM,
        )
        service.afterPropertiesSet()
        service
    }
}
