import os
from conseq import dep
from conseq import depquery
import flask
from flask_restful import Resource, Api

def flatten(d):
    pairs = []
    for k, v in d.items():
        if isinstance(v, dict):
            v = str(v)
        pairs.append((k,v))
    return dict(pairs)

class StoreQueries(Resource):
    def get_store(self):
        return flask.current_app.store
    def get_queries(self):
        query = flask.request.get_json()["query"]
        print("query", query)
        return query

class GetInstances(StoreQueries):
    def post(self):
        query = self.get_queries()
        ret = self.get_store().get_instances(query, [], None, 10000)
        ret["instances"] = [flatten(x) for x in ret["instances"]]
        print("GetInstances", ret)
        return ret

class FindProps(StoreQueries):
    def post(self):
        query = self.get_queries()
        return self.get_store().find_props(query, None, 10000)

class FindPropValues(StoreQueries):
    def post(self):
        query = self.get_queries()
        property = flask.request.get_json()["property"]
        return self.get_store().find_prop_values(query, property, None, 10000)

def main(state_dir):
    db_path = os.path.join("/Users/pmontgom/dev/crispr-analyses/state", "db.sqlite3")
    j = dep.open_job_db(db_path)
    instances = j.find_objs({})
    instances = [x.props for x in instances]
    store = depquery.AugmentedStore(instances)

    app = flask.Flask(__name__)
    app.store = store
    api = Api(app)
    api.add_resource(GetInstances, "/api/instances")
    api.add_resource(FindProps, "/api/props")
    api.add_resource(FindPropValues, "/api/values")

    app.run(debug=True)

if __name__ == "__main__":
    main("state")