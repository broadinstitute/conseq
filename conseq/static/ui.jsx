// state = {
//   predicates : list of (name, value) pairs,
// }

var PropConstButton = React.createClass({
  removeClicked: function (e) {
    this.props.removeCallback(this.props.index);
  },
  render: function () {
    return (
      <div className="row">
        <div className="altlabel">
          {this.props.label}{" "}
          <span
            className="glyphicon glyphicon-remove altbadge"
            onClick={this.removeClicked}
          ></span>
        </div>
      </div>
    );
  },
});

var upd = React.addons.update;

var CommonBlock = React.createClass({
  render: function () {
    var t = this;

    var header = this.props.properties.map(function (x, i) {
      return <th key={"h" + i}>{x} </th>;
    });

    var rows = [];

    for (var i = 0; i < t.props.instances.length; i++) {
      var instance = t.props.instances[i];
      var tds = this.props.properties.map(function (x, i) {
        return <td key={i}>{instance[x]} </td>;
      });

      rows.push(<tr key={i}>{tds}</tr>);
    }

    return (
      <table className="table table-striped">
        <tbody>
          <tr>{header}</tr>
          {rows}
        </tbody>
      </table>
    );
  },
});

var QueryTool = React.createClass({
  removeFilter: function (i) {
    console.log("state", this.state);
    var newState = upd(this.state, {
      valueSelection: { $set: "" },
      propertySelection: { $set: "" },
      predicates: { $splice: [[i, 1]] },
    });
    console.log("newState", newState);
    this.setState(newState);
    console.log("after setState", this.state);
    this.loadPropertyList(newState.predicates);
  },
  addFilter: function (e) {
    var pair = {
      property: this.state.propertySelection,
      value: this.state.valueSelection,
    };
    var newState = upd(this.state, {
      valueSelection: { $set: "" },
      propertySelection: { $set: "" },
      predicates: { $push: [pair] },
    });
    this.setState(newState);
    this.loadPropertyList(newState.predicates);
  },
  loadPropertyList: function (predicates) {
    var t = this;
    t.props.fetchProperties(predicates).then(function (properties) {
      var newState = upd(t.state, { properties: { $set: properties } });
      console.log("fetchProperties", newState);
      t.setState(newState);
    });

    t.props.fetchInstances(predicates).then(function (data) {
      console.log("fetchInstances", data);
      var newState = upd(t.state, { instances: { $set: data } });
      t.setState(newState);
    });
  },
  selectProperty: function (e) {
    var v = e.target.value;
    this.setState(upd(this.state, { propertySelection: { $set: v } }));
    var t = this;
    t.props.fetchValues(t.state.predicates, v).then(function (values) {
      var newState = upd(t.state, { values: { $set: values } });
      t.setState(newState);
    });
  },
  selectValue: function (e) {
    var v = e.target.value;
    this.setState(upd(this.state, { valueSelection: { $set: v } }));
    console.log("selectValue", v);
  },
  componentDidMount: function () {
    this.loadPropertyList([]);
  },
  getInitialState: function () {
    return {
      predicates: [],
      mode: "adding",
      propertySelection: "",
      valueSelection: "",
      properties: [],
      values: [],
      instances: { common: [], properties: [], instances: [] },
    };
  },
  render: function () {
    var t = this;
    var makeButton = function (pred, i) {
      return (
        <PropConstButton
          key={i}
          index={i}
          label={pred.property + " is " + pred.value}
          removeCallback={t.removeFilter}
        />
      );
    };

    var makeOptions = function (o, i) {
      // why does  ({o.count}) result in undef error?
      return (
        <option key={i} value={o.label}>
          {o.label}
        </option>
      );
    };

    var valueSelNodes = [];
    if (this.state.propertySelection != "") {
      var valueOptions = this.state.values.map(makeOptions);

      valueSelNodes.push("is");
      valueSelNodes.push(
        <div className="form-group">
          <select
            value={this.state.valueSelection}
            className="form-control"
            onChange={this.selectValue}
          >
            <option value="">Select value...</option>
            {valueOptions}
          </select>
        </div>
      );
      if (this.state.valueSelection != "") {
        valueSelNodes.push(
          <div className="form-group">
            <button className="btn" onClick={this.addFilter}>
              Add
            </button>
          </div>
        );
      }
    }

    console.log("this.state.properties", this.state.properties);
    var propertyOptions = this.state.properties.map(makeOptions);
    var e = (
      <div className="form-inline">
        <div className="form-group">
          <select
            value={this.state.propertySelection}
            className="form-control"
            onChange={this.selectProperty}
          >
            <option value="">Select property...</option>
            {propertyOptions}
          </select>
        </div>
        {valueSelNodes}
        <div>
          <CommonBlock
            instances={this.state.instances.instances}
            properties={this.state.instances.properties}
          />
        </div>
      </div>
    );

    var buttons = this.state.predicates.map(makeButton);
    return (
      <div>
        {buttons}
        <div className="row">{e}</div>
      </div>
    );
  },
});

var fetchProperties = function (query) {
  query = query.map(function (x) {
    return [x.property, x.value];
  });
  console.log("fetchProperties");
  console.log("query", query);
  return $.ajax("/api/props", {
    contentType: "application/json",
    dataType: "json",
    method: "POST",
    data: JSON.stringify({ query: query }),
  }).then(function (data) {
    console.log("data", data);
    var props = data["properties"];
    return props.map(function (x) {
      return { label: x[0], count: x[1] };
    });
  });
  //var result = [
  //      {label: "type", count: 10},
  //      {label: "name", count: 14},
  //      {label: "fruit", count: 14}
  //      ]
  //return new Promise(
  //      function(resolve, reject) {
  //          window.setTimeout(
  //              function() {
  //                  resolve(result);
  //              }, Math.random() * 1000 + 100);
  //      });
};

var fetchValues = function (query, property) {
  query = query.map(function (x) {
    return [x.property, x.value];
  });
  console.log("query", query);
  return $.ajax("/api/values", {
    contentType: "application/json",
    dataType: "json",
    method: "POST",
    data: JSON.stringify({ query: query, property: property }),
  }).then(function (data) {
    console.log("fetchValues result ", data);
    var values = data["values"];
    return values.map(function (x) {
      return { label: x[0], count: x[1] };
    });
  });
  //var result = [
  //        {label: "banana", count: 10},
  //      {label: "apple", count: 14}
  //      ]
  //return new Promise(
  //      function(resolve, reject) {
  //          window.setTimeout(
  //              function() {
  //                  resolve(result);
  //              }, Math.random() * 1000 + 100);
  //      });
};

var fetchInstances = function (query) {
  query = query.map(function (x) {
    return [x.property, x.value];
  });
  console.log("query", query);
  return $.ajax("/api/instances", {
    contentType: "application/json",
    dataType: "json",
    method: "POST",
    data: JSON.stringify({ query: query }),
  });
};

$(function () {
  var mountNode = document.getElementById("rootId");
  ReactDOM.render(
    <QueryTool
      fetchProperties={fetchProperties}
      fetchValues={fetchValues}
      fetchInstances={fetchInstances}
    />,
    mountNode
  );
});
