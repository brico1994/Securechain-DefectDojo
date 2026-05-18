from fastapi import FastAPI

#from app.api.routers.generic_findings import router as generic_findings_router
#
#
#def create_app() -> FastAPI:
#    app = FastAPI()
#
#    app.include_router(generic_findings_router, prefix="/generic-findings")
#    app.include_router(generic_findings_router, prefix="/api/defectdojo")
#    
#
#    return app

from app.controllers.generic_findings_controller import router as generic_findings_router


def create_app() -> FastAPI:
    app = FastAPI()

    app.include_router(
        generic_findings_router,
        prefix="/api/defectdojo/generic-findings",
    )

    return app

app = create_app()
