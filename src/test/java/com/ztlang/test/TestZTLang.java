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
    public final ControlPlane controlplane = new ControlPlane("control plane");
    
    public final User alice = new User("alice");
    public final User bob   = new User("bob");
    public final User charlie   = new User("charlie");
    // public final PEP pep = new PEP("pep");
    // public final PE pe = new PE("pe");
    // public final PA pa = new PA("pa");
    public final EnterpriseResource resource = new EnterpriseResource("resource");
    public final AccessPolicies accessPolicies = new AccessPolicies("access policies");
    public final Device alice_device = new Device("alice device", false);
    public final Device bob_device   = new Device("bob device"); //, true);
    public final Device charlie_device = new Device("charlie device", false);
    public final UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    public final UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
    public final UserCredentials charlie_credentials   = new UserCredentials("charlie_credentials");
    public final Agent alice_agent = new Agent("alice agent");
    public final Agent bob_agent = new Agent("bob agent");
    public final Agent charlie_agent = new Agent("charlie agent");

    public ZTLangModel() {
      // pa.addPep(pep);
      // pe.addPa(pa);
      // pep.addResource(resource);
      controlplane.addAgent(alice_agent);
      controlplane.addAgent(bob_agent);
      controlplane.addAgent(charlie_agent);
      controlplane.addResource(resource);

      // alice_agent.addResource(resource);
      // bob_agent.addResource(resource);
      // charlie_agent.addResource(resource);

      //pep.addUsers(alice);
      //pe.addDevice(alice_device);
      alice.addDevices(alice_device);
      alice.addUserCredentials(alice_credentials);
      alice_agent.addDevice(alice_device);
      //pe.addAgent(alice_agent);
      alice_agent.addUser(alice);
      alice.addResources(resource);

      //pep.addUsers(bob);
      //pe.addDevice(bob_device);
      bob.addDevices(bob_device);
      bob.addUserCredentials(bob_credentials);
      bob_agent.addDevice(bob_device);
      //pe.addAgent(bob_agent);
      bob_agent.addUser(bob);

      charlie.addDevices(charlie_device);
      charlie.addUserCredentials(charlie_credentials);
      charlie_agent.addDevice(charlie_device);
      //pe.addAgent(charlie_agent);
      charlie_agent.addUser(charlie);
      charlie.addResources(accessPolicies);

      accessPolicies.addUsers(alice);
      //accessPolicies.addResource(resource);
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
  public void testCompromiseIncompatibleDeviceAndCredentials2() {
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.bob_device.Compromise);
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

    model.resource.Access.assertUncompromised();
  }

  @Test
  public void testUntrustedDefense2() {
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.alice_device.Compromise);
    attacker.attack();

    model.resource.Access.assertCompromisedInstantaneously();
  }

  @Test
  public void testCompromiseAccessPoliciesAndPhishing() {
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.charlie_credentials.Compromise);
    attacker.addAttackPoint(model.charlie_device.Compromise);
    //attacker.addAttackPoint(model.accessPolicies.Access);
    attacker.addAttackPoint(model.alice_device.Compromise);
    attacker.attack();

    model.resource.Access.assertCompromisedInstantaneously();
  }

}
