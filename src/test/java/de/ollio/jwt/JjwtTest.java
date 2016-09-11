package de.ollio.jwt;

import de.ollio.keys.KeyReader;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.fest.assertions.Assertions.assertThat;

public class JjwtTest {
  private static final Logger log = Logger.getLogger(JjwtTest.class.getName());


  @Test
  public void testJjwt() throws Exception {
    String jwt = Jwts.builder()
        .setIssuer("Issuer")
        .setAudience("Audience")
        .setSubject("subject")
        .claim("partnerId", "WER03")
        .signWith(SignatureAlgorithm.RS512, KeyReader.readPrivateKey())
        .compact();

    assertThat(jwt).isNotEmpty();

    log.info("JWT len: " + jwt.length());
    log.info("JWT: " + jwt);

    Jws<Claims> claimsJws = Jwts.parser().setSigningKey(KeyReader.readPublicKey()).parseClaimsJws(jwt);

    assertThat(claimsJws.getBody().getIssuer()).isEqualTo("Issuer");
    assertThat(claimsJws.getBody().getSubject()).isEqualTo("subject");
    assertThat(claimsJws.getBody().get("partnerId")).isEqualTo("WER03");
  }


}
