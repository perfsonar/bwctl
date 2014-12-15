from bwctl.db.models import Base

engine = None

def init_db(db_str):
    engine = create_engine(db_str, echo=True)

    # get a handle on the metadata
    metadata = Base.metadata
    metadata.create_all(engine)

def get_db_engine():
    return engine
