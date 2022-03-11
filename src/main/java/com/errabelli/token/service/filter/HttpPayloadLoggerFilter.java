package com.errabelli.token.service.filter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.output.TeeOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class HttpPayloadLoggerFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(HttpPayloadLoggerFilter.class);

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		//Overriden method
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		final StringBuilder logMessage = new StringBuilder("REST Request - [HTTP METHOD:");
		BufferedRequestWrapper bufferedRequest = null;
		BufferedResponseWrapper bufferedResponse = null;
		String cdfSessionKey = null;
		String appSession = null;
		String f5Cookie = null;
		
		try {// main
			try {// request
				HttpServletRequest httpServletRequest = (HttpServletRequest) request;
				HttpServletResponse httpServletResponse = (HttpServletResponse) response;

				Map<String, String> requestMap = this.getTypesafeRequestMap(httpServletRequest);
				bufferedRequest = new BufferedRequestWrapper(httpServletRequest);
				bufferedResponse = new BufferedResponseWrapper(httpServletResponse);

				Cookie[] cookies = httpServletRequest.getCookies();
				if (cookies != null) {
					for (Cookie cookie : cookies) {
						if ("CSK".equals(cookie.getName())) {
							cdfSessionKey = cookie.getValue();
						} else if ("JSESSIONID".equals(cookie.getName())) {
							appSession = cookie.getValue();
						} else if (cookie.getName() != null && cookie.getName().toLowerCase().endsWith("suntrust.com")) {
							f5Cookie = cookie.getValue();
						}
					}
				}

				logMessage.append(httpServletRequest.getMethod()).append("] [PATH PARAMETERS:")
						.append(httpServletRequest.getServletPath()).append("] [QUERY PARAMETERS:").append(requestMap)
						.append("] [SELECTIVE-COOKIES:CSK=").append(cdfSessionKey).append(", JSESSIONID=").append(appSession)
						.append(", f5Cookie=").append(f5Cookie).append("] [REQUEST BODY:").append(bufferedRequest.getRequestBody())
						.append("] [REMOTE ADDRESS:").append(httpServletRequest.getRemoteAddr()).append("]");

			} catch (Exception a) {
				logger.error("HTTP request logging failed", a);
			}
			chain.doFilter(bufferedRequest, bufferedResponse);
			try {// response
				logMessage.append(" [RESPONSE:").append(bufferedResponse.getContent()).append("]");
			} catch (Exception a) {
				logger.error("HTTP response logging failed", a);
			}
		}

		finally {
			if (logger.isDebugEnabled() && logMessage != null) {
				logger.debug(logMessage.toString());
			}
		}
	}

	private Map<String, String> getTypesafeRequestMap(HttpServletRequest request) {
		Map<String, String> typesafeRequestMap = new HashMap<>();
		Enumeration<?> requestParamNames = request.getParameterNames();
		while (requestParamNames.hasMoreElements()) {
			String requestParamName = (String) requestParamNames.nextElement();
			String requestParamValue;
			if (requestParamName.equalsIgnoreCase("password")) {
				requestParamValue = "********";
			} else {
				requestParamValue = request.getParameter(requestParamName);
			}
			typesafeRequestMap.put(requestParamName, requestParamValue);
		}
		return typesafeRequestMap;
	}

	@Override
	public void destroy() {
		//Override
	}

	private static final class BufferedRequestWrapper extends HttpServletRequestWrapper {

		private byte[] buffer = null;

		public BufferedRequestWrapper(HttpServletRequest req) throws IOException {
			super(req);
			ByteArrayOutputStream baos = null;
			// Read InputStream and store its content in a buffer.
			InputStream is = req.getInputStream();
			baos = new ByteArrayOutputStream();
			byte[] buf = new byte[1024];
			int read;
			while ((read = is.read(buf)) > 0) {
				baos.write(buf, 0, read);
			}
			this.buffer = baos.toByteArray();
		}

		@Override
		public ServletInputStream getInputStream() {
			ByteArrayInputStream bais = null;
			BufferedServletInputStream bsis = null;
			bais = new ByteArrayInputStream(this.buffer);
			bsis = new BufferedServletInputStream(bais);
			return bsis;
		}

		String getRequestBody() throws IOException {
			StringBuilder inputBuffer = new StringBuilder();
			try (InputStreamReader inputStreamReader = new InputStreamReader(this.getInputStream());
					BufferedReader reader = new BufferedReader(inputStreamReader);) {
				String line = null;
				do {
					line = reader.readLine();
					if (null != line) {
						inputBuffer.append(line.trim());
					}
				} while (line != null);
			}
			return inputBuffer.toString().trim();
		}

	}

	private static final class BufferedServletInputStream extends ServletInputStream {

		private ByteArrayInputStream bais;

		public BufferedServletInputStream(ByteArrayInputStream bais) {
			this.bais = bais;
		}

		@Override
		public int available() {
			return this.bais.available();
		}

		@Override
		public int read() {
			return this.bais.read();
		}

		@Override
		public int read(byte[] buf, int off, int len) {
			return this.bais.read(buf, off, len);
		}

		@Override
		public boolean isFinished() {
			return false;
		}

		@Override
		public boolean isReady() {
			return true;
		}

		@Override
		public void setReadListener(ReadListener readListener) {
			//Overriden method
		}
	}

	public class BufferedResponseWrapper implements HttpServletResponse {

		HttpServletResponse original;
		TeeServletOutputStream tee;
		ByteArrayOutputStream bos;

		public BufferedResponseWrapper(HttpServletResponse response) {
			original = response;
		}

		public String getContent() {
			return (bos != null) ? bos.toString() : "";
		}

		public PrintWriter getWriter() throws IOException {
			return original.getWriter();
		}

		public ServletOutputStream getOutputStream() throws IOException {
			if (tee == null) {
				bos = new ByteArrayOutputStream();
				tee = new TeeServletOutputStream(original.getOutputStream(), bos);
			}
			return tee;

		}

		@Override
		public String getCharacterEncoding() {
			return original.getCharacterEncoding();
		}

		@Override
		public String getContentType() {
			return original.getContentType();
		}

		@Override
		public void setCharacterEncoding(String charset) {
			original.setCharacterEncoding(charset);
		}

		@Override
		public void setContentLength(int len) {
			original.setContentLength(len);
		}

		@Override
		public void setContentLengthLong(long l) {
			original.setContentLengthLong(l);
		}

		@Override
		public void setContentType(String type) {
			original.setContentType(type);
		}

		@Override
		public void setBufferSize(int size) {
			original.setBufferSize(size);
		}

		@Override
		public int getBufferSize() {
			return original.getBufferSize();
		}

		@Override
		public void flushBuffer() throws IOException {
			tee.flush();
		}

		@Override
		public void resetBuffer() {
			original.resetBuffer();
		}

		@Override
		public boolean isCommitted() {
			return original.isCommitted();
		}

		@Override
		public void reset() {
			original.reset();
		}

		@Override
		public void setLocale(Locale loc) {
			original.setLocale(loc);
		}

		@Override
		public Locale getLocale() {
			return original.getLocale();
		}

		@Override
		public void addCookie(Cookie cookie) {
			original.addCookie(cookie);
		}

		@Override
		public boolean containsHeader(String name) {
			return original.containsHeader(name);
		}

		@Override
		public String encodeURL(String url) {
			return original.encodeURL(url);
		}

		@Override
		public String encodeRedirectURL(String url) {
			return original.encodeRedirectURL(url);
		}

		@SuppressWarnings("deprecation")
		@Override
		public String encodeUrl(String url) {
			return original.encodeUrl(url);
		}

		@SuppressWarnings("deprecation")
		@Override
		public String encodeRedirectUrl(String url) {
			return original.encodeRedirectUrl(url);
		}

		@Override
		public void sendError(int sc, String msg) throws IOException {
			original.sendError(sc, msg);
		}

		@Override
		public void sendError(int sc) throws IOException {
			original.sendError(sc);
		}

		@Override
		public void sendRedirect(String location) throws IOException {
			original.sendRedirect(location);
		}

		@Override
		public void setDateHeader(String name, long date) {
			original.setDateHeader(name, date);
		}

		@Override
		public void addDateHeader(String name, long date) {
			original.addDateHeader(name, date);
		}

		@Override
		public void setHeader(String name, String value) {
			original.setHeader(name, value);
		}

		@Override
		public void addHeader(String name, String value) {
			original.addHeader(name, value);
		}

		@Override
		public void setIntHeader(String name, int value) {
			original.setIntHeader(name, value);
		}

		@Override
		public void addIntHeader(String name, int value) {
			original.addIntHeader(name, value);
		}

		@Override
		public void setStatus(int sc) {
			original.setStatus(sc);
		}

		@SuppressWarnings("deprecation")
		@Override
		public void setStatus(int sc, String sm) {
			original.setStatus(sc, sm);
		}

		@Override
		public String getHeader(String arg0) {
			return original.getHeader(arg0);
		}

		@Override
		public Collection<String> getHeaderNames() {
			return original.getHeaderNames();
		}

		@Override
		public Collection<String> getHeaders(String arg0) {
			return original.getHeaders(arg0);
		}

		@Override
		public int getStatus() {
			return original.getStatus();
		}

	}

	public class TeeServletOutputStream extends ServletOutputStream {

		private final TeeOutputStream targetStream;

		public TeeServletOutputStream(OutputStream one, OutputStream two) {
			targetStream = new TeeOutputStream(one, two);
		}

		@Override
		public void write(int arg0) throws IOException {
			this.targetStream.write(arg0);
		}

		@Override
		public void flush() throws IOException {
			super.flush();
			this.targetStream.flush();
		}
		
		@Override
		public void close() throws IOException {
			super.close();
			this.targetStream.close();
		}

		@Override
		public boolean isReady() {
			return false;
		}

		@Override
		public void setWriteListener(WriteListener writeListener) {
			//Overriden method
		}
	}

}
