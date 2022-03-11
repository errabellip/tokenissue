package com.errabelli.api.exception;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.web.DefaultErrorAttributes;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.errabelli.api.exception.entity.ErrorDetail;
import com.errabelli.api.exception.entity.ErrorResponse;

@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {
	private static Logger log = LoggerFactory.getLogger(RestExceptionHandler.class);
	
	@Bean
	public ErrorAttributes errorAttributes() {
		return new DefaultErrorAttributes() {
			@Override
			public Map<String, Object> getErrorAttributes(RequestAttributes requestAttributes,
					boolean includeStackTrace) {

				Map<String, Object> errorAttributes = super.getErrorAttributes(requestAttributes, includeStackTrace);
				log.error("errorAttributes={}", ReflectionToStringBuilder.toString(errorAttributes));
				log.error("includeStackTrace={}", includeStackTrace);

				HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
				Integer statusCodeInt = (Integer) errorAttributes.get("status");
				if (statusCodeInt != null) {
					status = HttpStatus.valueOf(statusCodeInt);
				}

				Date timestamp = (Date) errorAttributes.get("timestamp");
				SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
				String timestampStr = dateFormat.format(timestamp);

				String error = (String) errorAttributes.get("error");
				String exception = (String) errorAttributes.get("exception");
				String message = (String) errorAttributes.get("message");
				String path = (String) errorAttributes.get("path");
				StringBuilder stringBuilder = new StringBuilder().append("Failure [").append(message).append("] with ")
						.append("HTTP status ").append(statusCodeInt).append(" [" + error).append("] encountered at [")
						.append(timestampStr).append("], for path [").append(path).append("] with Exception [")
						.append(exception).append("]");

				log.error(stringBuilder.toString());

				ErrorResponse response = new ErrorResponse(status, ExceptionConstants.GENERAL_UNKNOWN_TYPE_FAILURE_CODE,
						message, timestamp.getTime());
				Map<String, Object> customErrorAttributes = new HashMap<String, Object>();
				customErrorAttributes.put("errors", response.getErrors());

				response.logErrorResponse();

				return customErrorAttributes;
			}

		};
	}
	
	@ExceptionHandler({ Exception.class })
	public ResponseEntity<Object> handleMasterException(Exception ex, WebRequest request) {
		log.error("Master exception handler", ex);
		return handleCustomizedException(new ServerException(ExceptionConstants.GENERAL_SERVER_FAILURE_CODE, "Server error", ex), request);
	}

	@Override
	protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		log.error("HttpMessageNotReadableException exception handler", ex);
		return handleCustomizedException(
				new BusinessException(ExceptionConstants.GENERAL_CLIENT_FAILURE_CODE, "Client request body not readable or parseable", ex),
				request);

	}

	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		log.error("MethodArgumentNotValidException exception handler", ex);

		BindingResult result = ex.getBindingResult();

		List<org.springframework.validation.FieldError> fieldErrors = result.getFieldErrors();
		ErrorResponse errorResponse = processFieldErrors(fieldErrors);
		return handleExceptionInternal(
				new BusinessException(ExceptionConstants.CLIENT_REQUEST_INCORRECT_CODE, "Client request incorrect", ex), errorResponse,
				headers, HttpStatus.BAD_REQUEST, request);
	}

	private ErrorResponse processFieldErrors(List<org.springframework.validation.FieldError> fieldErrors) {
		HttpStatus badClientRequestStatus = HttpStatus.BAD_REQUEST;

		ErrorResponse response = new ErrorResponse(badClientRequestStatus, ExceptionConstants.CLIENT_REQUEST_INCORRECT_CODE,
				"Client request incorrect");

		for (org.springframework.validation.FieldError fieldError : fieldErrors) {
			response.addError(new ErrorDetail(badClientRequestStatus, ExceptionConstants.CLIENT_REQUEST_INCORRECT_CODE,
					fieldError.getDefaultMessage(), fieldError.getField()));
		}
		return response;
	}

	@ExceptionHandler(BaseException.class)
	protected ResponseEntity<Object> handleBusinessAndServerException(BaseException exception, WebRequest request) {
		log.error("Business and Server exception handler" + exception.getClass(), exception);
		return handleCustomizedException(exception, request);
	}

	private ResponseEntity<Object> handleCustomizedException(BaseException exception, WebRequest request) {
		String rootCauseMessage = ExceptionUtils.getRootCauseMessage(exception);
		log.error("Handler logging error-" + rootCauseMessage + " - Uniq error ID:" + exception.getUniqueErrorId(), exception);
		String uniqueErrorId = exception.getUniqueErrorId();
		HttpStatus httpStatusCode = exception.getHttpStatusCode();
		String applicationCode = exception.getApplicationCode();
		String message = exception.getMessage();

		ErrorResponse response = new ErrorResponse(uniqueErrorId, httpStatusCode, applicationCode, message);
		response.logErrorResponse();

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);

		return new ResponseEntity<Object>(response, headers, exception.getHttpStatusCode());
	}
}
