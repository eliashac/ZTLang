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

public class TestDevice extends ZTLangTest {
  private static class ZTLangModel {
    public final ControlPlane controlplane = new ControlPlane("control plane");

    public final User alice = new User("alice");
    public final User bob   = new User("bob");
    public final EnterpriseResource resource = new EnterpriseResource("resource");
    public final Device alice_device = new Device("alice device", false);
    public final Device bob_device   = new Device("bob device"); //, true);
    public final UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    public final UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
    public final Agent alice_agent = new Agent("alice agent");
    public final Agent bob_agent = new Agent("bob agent");

    public final AccessPolicy alice_accesspolicy = new AccessPolicy("Alice acesspolicy");
    public final AccessPolicy bob_accesspolicy = new AccessPolicy("Bob acesspolicy");

    public ZTLangModel() {
      controlplane.addAgent(alice_agent);
      controlplane.addAgent(bob_agent);
      controlplane.addResources(resource);

      alice.addDevices(alice_device);
      alice.addUserCredentials(alice_credentials);
      alice_agent.addDevice(alice_device);
      alice_agent.addUser(alice);
      alice_accesspolicy.addResource(resource);
      alice.addAccessPolicy(alice_accesspolicy);

      bob.addDevices(bob_device);
      bob.addUserCredentials(bob_credentials);
      bob_agent.addDevice(bob_device);
      bob_agent.addUser(bob);
      bob_accesspolicy.addResource(resource);
      bob.addAccessPolicy(bob_accesspolicy);
    }
  }

  @Test
  public void testAccessResourceWithUntrustedDevice() {
    // Bobs device is untrusted and he tries to access a resource with his credentials
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.bob_credentials.Compromise);
    attacker.addAttackPoint(model.bob_device.Compromise);
    attacker.attack();

    model.resource.Access.assertUncompromised();
  }

  @Test
  public void testAccessResourceWithTrustedDevice() {
    // Alices device is trusted and he tries to access a resource with her credentials
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.alice_device.Compromise);
    attacker.attack();

    model.resource.Access.assertCompromisedInstantaneously();
  }

  @Test
  public void testAccessResourceWithAnotherUntrustedDevice() {
    // Alice uses Bobs untrusted device, and tries to access a resource with her (Alices) credentials
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.bob_device.Compromise);
    attacker.attack();

    model.resource.Access.assertUncompromised();
  }

  @Test
  public void testAccessResourceWithAnotherTrustedDevice() {
    // Bob uses Alices trusted device, and tries to access a resource with his (Bobs) credentials
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.bob_credentials.Compromise);
    attacker.addAttackPoint(model.alice_device.Compromise);
    attacker.attack();

    model.resource.Access.assertUncompromised();
  }

  @Test
  public void testAccessResourceWithoutDevice() {
    // Alices tries to access a resource without a device
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.attack();

    model.resource.Access.assertUncompromised();
  }
}
