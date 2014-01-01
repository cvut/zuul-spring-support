package cz.cvut.zuul.support.spring.provider

import org.springframework.http.HttpStatus
import org.springframework.http.client.ClientHttpResponse
import org.springframework.mock.http.client.MockClientHttpResponse
import org.springframework.web.client.ResponseErrorHandler
import spock.lang.Specification

class TokenValidationErrorHandlerTest extends Specification {

    def parentHandler = Mock(ResponseErrorHandler)
    def customHandler = new TokenValidationErrorHandler(parentHandler)


    def 'handle 409 response with InvalidClientTokenException'() {
        given:
            def response = new MockClientHttpResponse(new byte[0], HttpStatus.CONFLICT)
        when:
            customHandler.handleError(response)
        then:
            def ex = thrown(InvalidClientTokenException)
            ex.message == response.statusText
    }

    def 'handle other responses via parent handler'() {
        given:
            def response = new MockClientHttpResponse(new byte[0], HttpStatus.BAD_REQUEST)
        when:
            customHandler.handleError(response)
        then:
            1 * parentHandler.handleError(response)
    }

    def 'delegate hasError to parent handler'() {
        when:
            customHandler.hasError(_ as ClientHttpResponse)
        then:
            1 * parentHandler.hasError(_)
    }
}
