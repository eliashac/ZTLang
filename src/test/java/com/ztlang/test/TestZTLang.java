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
    public final PEP pep = new PEP("pep");
    public final PE pe = new PE("pe");
    public final PA pa = new PA("pa");
    public final EnterpriseResource resource = new EnterpriseResource("resource");
    public final Device device = new Device("device");

    public ZTLangModel() {
      pep.addUsers(alice);
      pa.addPep(pep);
      pe.addPa(pa);
      pep.addResource(resource);
      pe.addDevice(device);
    }
  }

  @Test
  public void testRequestAccess() {
    var model = new ZTLangModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.alice.RequestAccess);
    attacker.attack();

    //model.resource.Access.assertCompromisedInstantaneously();
    model.resource.Access.assertUncompromised();
  }

  @Test
  public void testRequestAccess2() {
    var model = new ZTLangModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.alice.RequestAccess);
    attacker.addAttackPoint(model.device.IsTrusted);
    attacker.attack();

    model.resource.Access.assertCompromisedInstantaneously();
  }
}
