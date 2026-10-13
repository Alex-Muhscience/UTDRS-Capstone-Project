from fastapi import APIRouter, BackgroundTasks, Depends

from core.models.scan import ScanReport, ScanResult
from core.services.detection_pipeline import analyse_event
from core.services.scan_service import ScanService
from utils.security import require_internal_token

router = APIRouter()


@router.post("/", response_model=ScanResult, dependencies=[Depends(require_internal_token)])
async def record_scan(report: ScanReport, background_tasks: BackgroundTasks):
    """
    Record a device scan from the device scanner.

    For UTDRS's own services: send INTERNAL_API_TOKEN in the X-Internal-Token header.

    The scan creates or updates the asset named after the device. The first scan of a
    device, or one whose inventory has changed, also raises an event, which is analysed
    like any other.
    """
    result, event = await ScanService().record_scan(report)
    if event and result.event_id:
        background_tasks.add_task(analyse_event, result.event_id, event)
    return result
