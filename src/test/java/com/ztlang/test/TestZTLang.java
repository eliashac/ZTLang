/*
 * Copyright 2020-2022 Foreseeti AB <https://foreseeti.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ztlang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class TestZTLang extends ZTLangTest {
  private static class ZTLangModel {
    public final User alice = new User("alice");
    public final User bob   = new User("bob");
    public final PEP pep = new PEP("pep");
    public final PE pe = new PE("pe");
    public final PA pa = new PA("pa");
    public final EnterpriseResource resource = new EnterpriseResource("resource");
    public final Device alice_device = new Device("alice device", true);
    public final Device bob_device   = new Device("bob device", true);
    public final UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    public final UserCredentials bob_credentials   = new UserCredentials("bob_credentials");

    public ZTLangModel() {
      pep.addUsers(alice);
      pep.addUsers(bob);

      pa.addPep(pep);

      pe.addPa(pa);
      pe.addDevice(alice_device);
      pe.addDevice(bob_device);

      pep.addResource(resource);

      alice.addDevices(alice_device);
      alice.addUserCredentials(alice_credentials);

      bob.addDevices(bob_device);
      bob.addUserCredentials(bob_credentials);
    }
  }

  @Test
  public void testCompromiseCredentialsButNotDevice1() {
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.attack();

    model.resource.Access.assertUncompromised();
  }

  @Test
  public void testCompromiseIncompatibleDeviceAndCredentials1() {
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.bob_credentials.Compromise);
    attacker.addAttackPoint(model.alice_device.Compromise);
    attacker.attack();

    model.resource.Access.assertUncompromised();
  }

  @Test
  public void testUntrustedDefense1() {
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.bob_credentials.Compromise);
    attacker.addAttackPoint(model.bob_device.Compromise);
    attacker.attack();

    model.resource.Access.assertCompromisedInstantaneously();
  }
  /*
  @Test
  public void testUntrustedDefense2() {
    var model = new ZTLangModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.alice_device.Compromise);
    attacker.attack();

    model.resource.Access.assertCompromisedInstantaneously();
  }
  */
}
