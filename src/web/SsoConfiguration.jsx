import React from "react";
import Reflux from "reflux";
import { Row, Col, Input, Button, Alert } from "react-bootstrap";

import SsoAuthActions from "SsoAuthActions";
import SsoAuthStore from "SsoAuthStore";

import Spinner from "components/common/Spinner";
import PageHeader from "components/common/PageHeader";
import ObjectUtils from 'util/ObjectUtils';

const SsoConfiguration = React.createClass({
  mixins: [
    Reflux.connect(SsoAuthStore),
  ],

  componentDidMount() {
    SsoAuthActions.config();
  },

  _saveSettings(ev) {
    ev.preventDefault();
    SsoAuthActions.saveConfig(this.state.config);
  },

  _setSetting(attribute, value) {
    const newState = {};

    // Clone state to not modify it directly
    const settings = ObjectUtils.clone(this.state.config);
    settings[attribute] = value;
    newState.config = settings;
    this.setState(newState);
  },


  _bindChecked(ev, value) {
    this._setSetting(ev.target.name, typeof value === 'undefined' ? ev.target.checked : value);
  },

  _bindValue(ev) {
    this._setSetting(ev.target.name, ev.target.value);
  },

  render() {
    let content;
    if (!this.state.config) {
      content = <Spinner />;
    } else {
      let trustedProxies = null;
      if (this.state.config.trusted_proxies) {
        trustedProxies = <span>
          The current subnet setting is: <code>{this.state.config.trusted_proxies}</code>. You can configure the setting in the Graylog server configuration file.
        </span>;
      } else {
        trustedProxies = <Alert bsStyle="danger">
          <h4 style={{ marginBottom: 5 }}>There are no trusted proxies set!</h4>
          <span>Please configure the <code>trusted_proxies</code> setting in the Graylog server configuration file.</span>
        </Alert>;
      }
      const subnetHelp = (<span>
        Enable this to require the request containing the SSO header as directly coming from a trusted proxy. This is highly recommended to avoid header injection.
        <br/>
        {trustedProxies}
      </span>);
      content = (
        <Row>
          <Col lg={8}>
            <form id="sso-config-form" className="form-horizontal" onSubmit={this._saveSettings}>
              <fieldset>
                <legend className="col-sm-12">Header configuration</legend>
                <Input type="text" id="certificate_header" name="certificate_header" labelClassName="col-sm-3"
                       wrapperClassName="col-sm-9" placeholder="Remote-User" label="Username Header"
                       value={this.state.config.certificate_header} help="HTTP header containing the certificate of the Graylog user"
                       onChange={this._bindValue} required/>
              </fieldset>
              <fieldset>
                <legend className="col-sm-12">Security</legend>
                <Input type="checkbox" label="Request must come from a trusted proxy"
                       help={subnetHelp}
                       wrapperClassName="col-sm-offset-3 col-sm-9"
                       name="require_trusted_proxies"
                       checked={this.state.config.require_trusted_proxies}
                       onChange={this._bindChecked}/>
              </fieldset>
              <fieldset>
                <legend className="col-sm-12">User creation</legend>
                <Input type="checkbox" label="Automatically create users"
                       help="Enable this if Graylog should automatically create a user account for externally authenticated users. If disabled, an administrator needs to manually create a user account."
                       wrapperClassName="col-sm-offset-3 col-sm-9"
                       name="auto_create_user"
                       checked={this.state.config.auto_create_user}
                       onChange={this._bindChecked}/>
                <Input id="default_group" labelClassName="col-sm-3"
                       wrapperClassName="col-sm-9" label="Default User Role"
                       help="The default Graylog role determines whether a user created can access the entire system, or has limited access.">
                  <Row>
                    <Col sm={6}>
                      <select id="default_group" name="default_group" className="form-control" required
                              value={this.state.config.default_group}
                              onChange={this._bindValue} disabled={!this.state.config.auto_create_user}>

                        <option value="Reader">Reader - basic access</option>
                        <option value="Admin">Administrator - complete access</option>
                      </select>
                    </Col>
                  </Row>
                </Input>
              </fieldset>
              <fieldset>
                <legend className="col-sm-12">Store settings</legend>
                <div className="form-group">
                  <Col sm={9} smOffset={3}>
                    <Button type="submit" bsStyle="success">Save SSO settings</Button>
                  </Col>
                </div>
              </fieldset>
            </form>
          </Col>
        </Row>
      );
    }

    return (
      <div>
        <PageHeader title="Single Sign-On Configuration" subpage>
          <span>Configuration page for the TLS SSO authenticator.</span>
          {null}
        </PageHeader>
        {content}
      </div>
    );
  },
});

export default SsoConfiguration;
