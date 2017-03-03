import pickle

with open("search_terms.p", "rb") as existing:
    data_store = pickle.load(existing)

# Do stuff here to change the search_terms.p etc. eg:
# data_store["net use"]["pattern"] = "net use"

with open("search_terms.p", "wb") as changed:
    pickle.dump(data_store, changed)
