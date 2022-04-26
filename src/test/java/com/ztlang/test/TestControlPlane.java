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

public class TestControlPlane extends ZTLangTest {

  @Test
  public void testNoCompromiseOfResourceNotAddedToControlPlane() {
    // Alice has access to the resource and her device and credentials are compromised
    // The resource has not been added to the controlPlane so the attacker does not get access

    // Verifies requirement 1 (access is only made through the control plane)

    ControlPlane controlplane = new ControlPlane("control plane");
    User alice = new User("alice");
    EnterpriseResource resource = new EnterpriseResource("resource");
    Device alice_device = new Device("alice device", false);
    UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    Agent alice_agent = new Agent("alice agent");
    AccessPolicy alice_accesspolicy = new AccessPolicy("Alice acesspolicy");

    controlplane.addAgent(alice_agent);
    // The resource is not added to the controlPlane
    alice.addDevices(alice_device);
    alice.addUserCredentials(alice_credentials);
    alice_agent.addDevice(alice_device);
    alice_agent.addUser(alice);
    alice.addAccessPolicy(alice_accesspolicy);
    alice_accesspolicy.addUser(alice);
    alice_accesspolicy.addResource(resource);

    var attacker = new Attacker();

    attacker.addAttackPoint(alice_credentials.Compromise);
    attacker.addAttackPoint(alice_device.Compromise);

    resource.Access.assertUncompromised();
  }
}
