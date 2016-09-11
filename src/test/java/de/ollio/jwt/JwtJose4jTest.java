package de.ollio.jwt;

import de.ollio.keys.KeyReader;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.testng.annotations.Test;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.fest.assertions.Assertions.assertThat;

public class JwtJose4jTest {
  private static final Logger log = Logger.getLogger(JwtJose4jTest.class.getName());


  @Test
  public void testJose4j() throws Exception {
    JwtClaims claims = new JwtClaims();
    claims.setIssuer("Issuer");  // who creates the token and signs it
    claims.setAudience("Audience"); // to whom the token is intended to be sent
    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
    claims.setGeneratedJwtId(); // a unique identifier for the token
    claims.setIssuedAtToNow();  // when the token was issued/created (now)
    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
    claims.setSubject("subject"); // the subject/principal is whom the token is about
    claims.setClaim("partnerId","WER03"); // additional claims/attributes about the subject can be added
    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array

    JsonWebSignature jws = new JsonWebSignature();

    jws.setPayload(claims.toJson());
    jws.setKey(KeyReader.readPrivateKey());
    jws.setKeyIdHeaderValue("K1");
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

    String jwt = jws.getCompactSerialization();

    assertThat(jwt).isNotEmpty();

    log.info("JWT len: " + jwt.length());
    log.info("JWT: " + jwt);

    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setRequireExpirationTime() // the JWT must have an expiration time
        .setMaxFutureValidityInMinutes(300) // but the  expiration time can't be too crazy
        .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
        .setRequireSubject() // the JWT must have a subject claim
        .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
        .setExpectedAudience("Audience") // to whom the JWT is intended for
        .setVerificationKey(KeyReader.readPublicKey()) // verify the signature with the public key
        .build(); // create the JwtConsumer instance

    JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);

    assertThat(jwtClaims.getIssuer()).isEqualTo(claims.getIssuer());
    assertThat(jwtClaims.getSubject()).isEqualTo(claims.getSubject());
    assertThat(jwtClaims.getClaimValue("partnerId")).isEqualTo("WER03");
  }


}
